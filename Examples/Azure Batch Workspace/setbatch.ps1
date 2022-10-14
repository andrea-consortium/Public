<#
.DESCRIPTION
Adds or removes azure batch to or from a anDREa workspace
User MUST be in role 'Owner' on the resource group.
Resources that already exist are not modified.
Requires Az modules installed (duh...)
.PARAMETER SubscriptionID
The subscription of the workspace to add the batch account
.PARAMETER Workspace
The workspace name to add the batch account to. Must be a valid workspace
.PARAMETER Headnode
[optional] The name of a VM (resource name) that will act as the head node for the HPC cluster (i.e. the machine running nextflow). If empty, will select the first linux VM in the workspace or error out if none exists.
.PARAMETER LowPrioCoreQuota
[optional] (initial) Low prio core quota. Can be changed later via Azure batch interface in azure portal
.PARAMETER DedicatedCoreQuota
[optional] (initial) Normal prio core quota. Can be changed later via Azure batch interface in azure portal
.PARAMETER BatchVnetCIDR
[optional] CIDR of the batch vnet. Default should be sufficient in pretty much all cases.
.PARAMETER Remove
[optional] Remove batch environment instead of removing it. Will undo any actions taken by this script
.EXAMPLE
Set-AzureBatch -SubscriptionID c35d7786-0627-4514-90b9-48ff66b6f1d4 -workspace dws-001-batch -headNode dws001batchserver3
#>
function Set-WorkspaceBatch {
    [CmdletBinding()]
    Param(
        [string]$SubscriptionID,
        [string]$Workspace,
        [string]$Headnode = $null,
        [int]$LowPrioCoreQuota = 96,
        [int]$DedicatedCoreQuota = 96,
        [string]$BatchVnetCIDR = '172.16.0.0/16',
        [switch]$Remove = $false
    )

    $ErrorActionPreference = 'Stop'
    write-host "selecting subscription $SubscriptionID"
    Select-AzSubscription -SubscriptionId $SubscriptionID | Out-Null

    $rg = Get-AzResourceGroup -Name $Workspace -ErrorAction SilentlyContinue
    if (-not $rg) {
        throw 'Resource group not found'
    }

    $wgbasename = $rg.ResourceGroupName.Replace('-', '').ToLower()
    $vnetName = "$wgbasename-batch-vnet"
    $nsgName = "z$wgbasename-batch-nsg" #must be lower alphabetic prio than existing nsgs, otherwise mydre portal breaks.
    $plName = "$wgbasename-batch-link"
    $peName = "$wgbasename-batch-endpoint"
    $batchName = if ($wgbasename.Length -gt (19 - $num.Length)) { "$($wgbasename.Substring(0, 19 - $num.Length))batch" } else { "$($wgbasename)batch" }

    Write-Host "Searching for existing resources"
    $sa = Get-AzStorageAccount -ResourceGroupName $rg.ResourceGroupName -Name "$($rg.ResourceGroupName.Replace('-',''))data" | Select-Object -First 1
    $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
    $nsg = Get-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
    $batch = Get-AzBatchAccount -AccountName $batchName -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
    $pe = Get-AzPrivateEndpoint -Name $peName -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
    
    if($sa) { write-host "Found workspace storage account $($sa.storageAccountName)" }
    if($vnet) { write-host "Found batch vnet $($vnet.Name)" }
    if($nsg) { write-host "Found batch nsg $($nsg.Name)" }
    if($batch) { write-host "Found batch account $($batch.AccountName)" }
    if($pe) { write-host "Found private endpoint $($pe.Name)" }

    if (-not $sa) {
        throw 'Could not find storage account'
    }

    if (-not $Remove) {
        if (-not $nsg) {
            $nsg = New-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $rg.ResourceGroupName -Location $rg.Location -SecurityRules @(
                (New-AzNetworkSecurityRuleConfig -Name 'AllowNodeManagementInbound' -Protocol Tcp -Access Allow -Direction Inbound -Priority 100 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange @(10100, 20100, 30100)),
                (New-AzNetworkSecurityRuleConfig -Name 'AllowBatchNodeManagementInbound' -Protocol Tcp -Access Allow -Direction Inbound -Priority 200 -SourceAddressPrefix BatchNodeManagement -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange @(29876, 29877)),
                (New-AzNetworkSecurityRuleConfig -Name 'DenyAnyInbound' -Protocol Tcp -Access Deny -Direction Inbound -Priority 300 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange *),
                (New-AzNetworkSecurityRuleConfig -Name 'AllowBatchNodeManagementOutbound' -Protocol Tcp -Access Allow -Direction Outbound -Priority 100 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix BatchNodeManagement -DestinationPortRange 443),
                (New-AzNetworkSecurityRuleConfig -Name 'AllowStorageOutbound' -Protocol Tcp -Access Allow -Direction Outbound -Priority 200 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix Storage -DestinationPortRange 443),
                (New-AzNetworkSecurityRuleConfig -Name 'DenyInternetOutbound' -Protocol Tcp -Access Deny -Direction Outbound -Priority 1000 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix Internet -DestinationPortRange *)
            )
        }
        if (-not $vnet) {
            Write-Host "Creating vnet $vnetName with default subnet $BatchVnetCIDR"
            $vnet = New-AzVirtualNetwork -Name $vnetName -ResourceGroupName $rg.ResourceGroupName -AddressPrefix $BatchVnetCIDR `
                -Location $rg.Location -Subnet (New-AzVirtualNetworkSubnetConfig -Name default -AddressPrefix $BatchVnetCIDR -NetworkSecurityGroup $nsg -ServiceEndpoint @('Microsoft.Storage') )
            Add-AzStorageAccountNetworkRule -ResourceGroupName $rg.ResourceGroupName -Name $sa.StorageAccountName -VirtualNetworkResourceId $vnet.Subnets[0].Id | Out-Null       
        }
        if (-not $batch) {
            Write-Host "Creating batch account $batchName with publicNetworkAccess disabled, $LowPrioCoreQuota Low Prio core quota and $DedicatedCoreQuota dedicated core quota"
            $batch = New-AzBatchAccount -AccountName $batchName -Location $rg.Location -ResourceGroupName $rg.ResourceGroupName -PoolAllocationMode BatchService -PublicNetworkAccess Disabled -IdentityType SystemAssigned
            $batchres = Get-AzResource -ResourceId $batch.Id
            $batchres.Properties.dedicatedCoreQuotaPerVMFamilyEnforced = $false
            $batchres.Properties.lowPriorityCoreQuota = $LowPrioCoreQuota
            $batchres.Properties.dedicatedCoreQuota = $DedicatedCoreQuota
            $batchres.Properties.dedicatedCoreQuotaPerVMFamilyEnforced = $false
            $batchres | Set-AzResource -Force
        }
        if (-not $pe) {
            Write-Host "Creating private endpoint/link $peName/$plName for batch account and adding it to the workspace subnet. This might take a while"
            $wssubnetrule = $sa.NetworkRuleSet.VirtualNetworkRules | Where-Object { $_.VirtualNetworkResourceId.ToLower().IndexOf('/workspace-vnet/') } | Select-Object -First 1
            $wssubnetresource = get-azResource -ResourceId $wssubnetrule.VirtualNetworkResourceId
            $wsvnet = Get-AzVirtualNetwork -ResourceGroupName $wssubnetresource.ResourceGroupName -Name $wssubnetresource.ParentResource.Split('/')[1]
            $wssubnet = $wsvnet.Subnets | Where-Object { $_.Name -eq $wssubnetresource.Name }
            $conn = New-AzPrivateLinkServiceConnection -Name $plName -PrivateLinkServiceId $batch.ID -GroupID 'batchAccount' -ErrorAction SilentlyContinue
            $pe = New-AzPrivateEndpoint -ResourceGroupName $rg.ResourceGroupName -Name $peName -Location $rg.Location -Subnet $wssubnet -PrivateLinkServiceConnection $conn
        }
    }

    if (-not $Headnode) {
        Write-Host "Finding headnode candidate"
        $vms = get-azvm -ResourceGroupName $rg.ResourceGroupName
        foreach($vm in $vms) {
            if ($vm.StorageProfile.OsDisk.OsType -eq 'Linux') {
                $HeadnodeVM = $vm
                break
            }
        }
    } else {
        $HeadnodeVM = get-azvm -ResourceGroupName $rg.ResourceGroupName -Name $Headnode -ErrorAction SilentlyContinue
    }
    if (-not $HeadnodeVM) {
        throw 'No suitable headnode found'
    } else {
        write-host "Using $($HeadnodeVM.Id) as headnode"
    }
    $ident = $HeadnodeVM.Identity.PrincipalId

    if ($Remove) {
        foreach($roleassignment in (Get-AzRoleAssignment -ObjectId $ident | Where-Object { @($batch.Id, $vnet.Id, $rg.ResourceId) -contains $_.Scope })) {
            Remove-AzRoleDefinition -Id $roleassignment.RoleDefinitionId -Scope $roleassignment.Scope -Force | Out-Null
        }

        if ($batch) {
            Write-Host "Removing batch account $($batch.AccountName)"
            Remove-AzBatchAccount -AccountName $batch.AccountName -ResourceGroupName $rg.ResourceGroupName -Force | Out-Null
        }
        
        $rule = $sa.NetworkRuleSet.VirtualNetworkRules | Where-Object {  $_.VirtualNetworkResourceId.StartsWith($vnet.id) }
        if ($rule) {
            Write-Host "Removing storage account network rule for batch vnet"
            $rule | Remove-AzStorageAccountNetworkRule -ResourceGroupName $rg.ResourceGroupName -Name $sa.StorageAccountName | Out-Null
        }
        if ($pe) {
            Write-Host "Removing private endpoint $($pe.Name)"
            Remove-AzPrivateEndpoint -ResourceGroupName $rg.ResourceGroupName -Name $pe.Name -Force | Out-Null
        }
        if ($vnet) {
            Write-Host "Removing virtual network $($vnet.Name)"
            Remove-AzVirtualNetwork -Name $vnet.Name -ResourceGroupName $rg.ResourceGroupName -Force | Out-Null
        }
        if ($nsg) {
            Write-Host "Removing network security group $($nsg.Name)"
            Remove-AzNetworkSecurityGroup -Name $nsg.Name -ResourceGroupName $rg.ResourceGroupName -Force | Out-Null
        }
        Get-AzPolicyAssignment -Name 'DisablePublicBatchAccountAccessPolicyAssignment' -Scope $rg.ResourceId -ErrorAction SilentlyContinue | Remove-AzPolicyAssignment

    } else {
        foreach($subscription in Get-AzSubscription) {
            Select-AzSubscription -Subscription $Subscription | Out-Null
            $role = Get-AzRoleDefinition -Name "Dre Batch Manager" -ErrorAction SilentlyContinue
            if ($role) {
                break;
            }
        }
        Select-AzSubscription -SubscriptionID $SubscriptionID | Out-Null
        if ($role -and -not $role.AssignableScopes.Contains("/subscriptions/$SubscriptionID")) {
            Write-Host "Updating 'Dre Batch Manager' role definition so it can be used in the subscription"
            $role.AssignableScopes.Add("/subscriptions/$SubscriptionID")
            $tempfile = New-TemporaryFile
            $role | ConvertTo-Json -depth 10 | Out-File $tempfile.FullName
            Set-AzRoleDefinition -InputFile $tempfile.FullName | Out-Null

        } elseif (-not $role) {
            Write-Host "Adding 'Dre Batch Manager' role definition to the subscription"
            $tempfile = New-TemporaryFile
            $role = @{
                "Name" = "Dre Batch Manager"
                "Id" = "3e82341d-22a7-46ab-bc8b-22a3705a1399"
                "IsCustom" = $true
                "Description" = "Can manage batch accounts"
                "Actions" = @(
                    "Microsoft.Network/privateEndpoints/read",
                    "Microsoft.Network/virtualNetworks/read",
                    "Microsoft.Network/virtualNetworks/subnets/read",
                    "Microsoft.Network/privateLinkServices/read",
                    "Microsoft.Network/privateLinkServices/privateEndpointConnections/read",
                    "Microsoft.Batch/batchAccounts/*"
                )
                "NotActions" = @()
                "DataActions" = @()
                "NotDataActions" = @()
                "AssignableScopes" = @(
                    "/subscriptions/$($SubscriptionID)"
                )
            }
            $role | ConvertTo-Json -depth 10 | Out-File $tempfile.FullName
            New-AzRoleDefinition -InputFile $tempfile.FullName | Out-Null
        }
        if (-not (Get-AzPolicyDefinition -Name 'DisablePublicBatchAccountAccess' -SubscriptionId $SubscriptionID -ErrorAction SilentlyContinue)) {
            Write-Host "Creating policy to disable public batch account access"
            $definition = New-AzPolicyDefinition -Name 'DisablePublicBatchAccountAccess' -SubscriptionId $SubscriptionID -Policy @"
    {
        "properties": {
            "category": "Batch",
            "displayName": "Deny batch accounts using public network",
            "description": "Deny batch accounts using public network. Checks networkaccess = Deny",
            "mode": "all",
            "parameters": {
                "effectType": {
                    "type": "string",
                    "defaultValue": "Deny",
                    "allowedValues": [
                        "Deny",
                        "Disabled"
                    ],
                    "metadata": {
                        "displayName": "Effect",
                        "description": "Enable or disable the execution of the policy"
                    }
                }
            },
            "policyRule": {
                "if": {
                    "allOf": [
                        {
                            "field": "type",
                            "equals": "Microsoft.Batch/batchAccounts"
                        },
                        {
                            "anyOf": [
                                {
                                    "field": "Microsoft.Batch/batchAccounts/publicNetworkAccess",
                                    "notEquals": "Disabled"
                                },
                                {
                                    "field": "Microsoft.Batch/batchAccounts/networkProfile.AccountAccess.defaultAction",
                                    "notEquals": "Deny"
                                },
                                {
                                    "count": {
                                        "field": "Microsoft.Batch/batchAccounts/networkProfile.AccountAccess.ipRules[*]"
                                    },
                                    "notEquals": 0
                                }

                            ]
                        }
                    ]
                },
                "then": {
                    "effect": "[parameters('effectType')]"
                }
            }
        }
    }
"@
    $params = @{
        'effectType' = 'Deny'
    }
    $definition = Get-AzPolicyDefinition -Name 'DisablePublicBatchAccountAccess'
    New-AzPolicyAssignment -Name 'DisablePublicBatchAccountAccessPolicyAssignment' -PolicyDefinition $definition -Scope $rg.ResourceId -PolicyParameterObject $params | Out-Null
        }
        Write-Host "Creating roles"
        New-AzRoleAssignment -ObjectId $ident -Scope $vnet.Id -RoleDefinitionName 'Virtual Machine Contributor' -ErrorAction SilentlyContinue | Out-Null
        New-AzRoleAssignment -ObjectId $ident -Scope $batch.Id -RoleDefinitionName 'Contributor' -ErrorAction SilentlyContinue | Out-Null
        New-AzRoleAssignment -ObjectId $ident -Scope $rg.ResourceId -RoleDefinitionName 'Dre Batch manager' -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Host "All done. Have a good day!"
}