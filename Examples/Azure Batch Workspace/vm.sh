#!/bin/bash
apt update
apt install default-jre python3 pip python-is-python3 -y

cd '/usr/local/bin'
wget -qO- https://get.nextflow.io | bash
wget 'https://github.com/nextflow-io/azcopy-tool/raw/linux_amd64_10.8.0/azcopy' -O 'azcopy'
chmod +x nextflow
chmod +x azcopy
nextflow self-update
cd /tmp
cat << EOF > /tmp/nextflow.config
manifest {
    name = "test"
    mainScript = "t.nf"
    nextflowVersion = ">=21.04.0"
    version = "1.0.0"
}

process {
    executor = "azurebatch"
    withName: SLEEP
    {
        queue="foo"
    }
}

azure {
    storage {
        accountName = "aa"
        accountKey = "bb"
    }
    batch {
        endpoint = "https://x.westeurope.batch.azure.com"
        accountName = "cc"
        accountKey = "dd"
        pools {
            foo {
                autoScale = false
            }
        }
    }
}
EOF
cat << EOF > /tmp/t.nf
#!/usr/bin/env nextflow

items = Channel.of(1,2,3,4,5)
process SLEEP {

    tag "\$x"

    container "a.b.c.d"

    input:
        val x from items

    script:
    """
    sleep \$x
    """
}
EOF
nextflow run /tmp/t.nf -plugins nf-azure
mkdir -p /usr/local/bin/nextflow-plugins
cp -r ~/.nextflow/plugins/* /usr/local/bin/nextflow-plugins/
rm -r -f /tmp/*
cat << EOF > "/usr/local/bin/nextflowplugins"
#!/bin/bash
mkdir -p ~/.nextflow/plugins
cp -rf /usr/local/bin/nextflow-plugins/* ~/.nextflow/plugins/
EOF
chmod +x /usr/local/bin/nextflowplugins

###########################
libPath=$(python -c "from distutils import sysconfig;print(sysconfig.get_python_lib())")
mkdir -p "$libPath/nextflowhelper"
cat << EOF > "$libPath/nextflowhelper/__init__.py"
import re
import os
import time

from typing import Optional, List, Dict, Tuple
from datetime import datetime, timedelta
from azure.storage.blob import BlobClient, BlobServiceClient, generate_blob_sas, BlobSasPermissions
from azure.mgmt.batch import BatchManagementClient
from azure.identity import ManagedIdentityCredential, DeviceCodeCredential
from azure.batch import BatchServiceClient
from azure.batch.models import PoolAddParameter,VirtualMachineConfiguration,ImageReference,NetworkConfiguration,ContainerConfiguration,StartTask,AutoUserSpecification,UserIdentity,ImageInformation,CloudPoolPaged,AllocationState
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from msrest.authentication import BasicTokenAuthentication
from azure.core.pipeline.policies import BearerTokenCredentialPolicy
from azure.core.pipeline import PipelineRequest, PipelineContext
from azure.core.pipeline.transport import HttpRequest
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import SecurityRule, NetworkSecurityGroup

class PoolStatus:
    PoolStatus: str
    AllocationStatus: AllocationState
    NodeStatus: Dict[str,str]

class NetworkRule:
    def __init__(self, name: str, priority: int, cidr: str, port: str, access: str, description: str):
        self.name = name
        self.priority = priority
        self.cidr = cidr
        self.port = port
        self.access = access
        self.description = description
    name: str
    priority: int
    cidr: str
    port: str
    access: str
    description: str

class NextflowHelper:
    '''
    Class for creating and managing batch pools for use in nextflow (or other compatible applications)
    The class also provides usefull clients for network management (whitelist ip-addresses available to the batch nodes) and the storage account of the workspace

    Authenticates using Managed service principal
    For manipulating network rules, user must log in with their own credentials using microsofts' device code credential flow.
    To do so, follow the instructions when asked to open up a browser to https://microsoft.com/devicelogin (on a device WITH internet access) and entering hte code displayed on screen
    '''

    _DEFAULT_SCALING_FORMULA = '''// Get pool lifetime since creation.
        lifespan = time() - time("{poolCreationTime}");
        interval = TimeInterval_Minute * {scaleInterval};
        // Compute the target nodes based on pending tasks.
        // \$PendingTasks == The sum of \$ActiveTasks and \$RunningTasks
        \$samples = \$PendingTasks.GetSamplePercent(interval);
        \$tasks = \$samples < 70 ? max(0, \$PendingTasks.GetSample(1)) : max( \$PendingTasks.GetSample(1), avg(\$PendingTasks.GetSample(interval)));
        \$targetVMs = \$tasks > 0 ? \$tasks : max(0, \$TargetDedicatedNodes/2);
        targetPoolSize = max(0, min(\$targetVMs, {maxVmCount}));
        // For first interval deploy 1 node, for other intervals scale up/down as per tasks.
        \$TargetDedicatedNodes = lifespan < interval ? {vmCount} : targetPoolSize;
        \$NodeDeallocationOption = taskcompletion;'''
    _subscription: str = None
    _resource_group: str = None
    _client: BatchServiceClient = None
    _cred: None

    def __init__(self):
        self._cred = DeviceCodeCredential()
        _ = self.get_resource_group()
        _ = self.get_subscription_id()
    def get_subscription_id(self) -> str:
        '''
        Get a subscription client on behalf of the VM's identity. This client has limited access (readonly) to the workspace resource group and not much else
        '''
        if self._subscription is None:
            self._subscription = SubscriptionClient(self.get_credentials(True)).subscriptions.list().next().subscription_id
        return self._subscription
    def get_resource_group(self) -> str:
        '''
        Returns the name of the resourcegroup (workspace name)
        '''
        if self._resource_group is None:
            client = StorageManagementClient(self.get_credentials(True), self.get_subscription_id())
            sa = next(client.storage_accounts.list())
            self._resource_group = sa.id.split('/')[4]
        return self._resource_group
    def get_credentials(self, vmauth: bool):
        '''
        Returns an instance of TokenCredentials class that can be used to authenticate to Azure services using the VM's identity.
        '''
        return (self._cred if not vmauth else ManagedIdentityCredential())
    def get_network_client(self):
        '''
        Returns an instance of TokenCredentials class that can be used to authenticate to Azure services using the Users identity.

        NOTE: requires device code credentials obo user that is using the service
        '''
        return NetworkManagementClient(credential=self.get_credentials(False), subscription_id=self.get_subscription_id())
    def get_batch_nsg(self) -> NetworkSecurityGroup:
        client = self.get_network_client()
        rg = self.get_resource_group()
        for nsg in client.network_security_groups.list(rg):
            if nsg.subnets is not None and len(nsg.subnets) == 1 and f'/resourcegroups/{rg.lower()}/' in nsg.subnets[0].id.lower():
                return nsg
        return None
    def list_network_rules(self):
        ''' 
        Returns a list of current network rules (possible open internet connections) on the batch vnet
        There can be up to 500 rules in total (active + inactive)

        returns list[NetworkRule]
        '''
        nsg = self.get_batch_nsg()
        if nsg is None:
            raise Exception('Could not find any nsg related to batch vnet')
        ret = list()
        for rule in nsg.security_rules:
            if rule.direction == 'Outbound' and rule.priority > 500 and rule.priority <= 1000:
                ret.append(NetworkRule(rule.name, rule.priority, rule.destination_address_prefix, rule.destination_port_range, rule.access, rule.description))
        return ret
    def delete_network_rule(self, name: str):
        '''
        Delete (make inactive) existing network rule identified by name and returns modified rule

        return NetworkRule or raises exception
        '''
        client = self.get_network_client()
        nsg = self.get_batch_nsg()
        for rule in nsg.security_rules:
            if rule.name == name and rule.direction == 'Outbound' and rule.priority > 500 and rule.priority <= 1000:
                rule.access = 'Deny'
                r = client.security_rules.begin_create_or_update(self.get_resource_group(), nsg.name, rule.name, rule)
                r.wait()
                return NetworkRule(rule.name, rule.priority, rule.destination_address_prefix, rule.destination_port_range, rule.access, rule.description)
        raise Exception(f'Rule {name} not found')
    def create_network_rule(self, cidr: str, port: str='443', description: str = None):
        '''
        Create network rule (if not already here) or updates network rule (if already there and inactive) and returns corresponding rule
        
        helper.create_network_rule('1.2.3.4', '443', 'Some optional description') #enable port 443 to 1.2.3.4
        helper.create_network_rule('Internet', '443') #enable port 443 to all of internet
        helper.create_network_rule('1.2.3.4', '*') #enable all ports to 1.2.3.4

        returns NetworkRule or None if nothing was changed
        '''
        client = self.get_network_client()
        nsg = self.get_batch_nsg()
        prio = 501
        for rule in nsg.security_rules:
            if rule.destination_address_prefix == cidr and (rule.destination_port_range == port or cidr.lower() == 'internet') and rule.direction == 'Outbound' and rule.priority > 500 and rule.priority <= 1000:
                if rule.description != description and description is not None or rule.access == 'Deny':
                    rule.description = description
                    rule.access = 'Allow'
                    r = client.security_rules.begin_create_or_update(self.get_resource_group(), nsg.name, rule.name, rule)
                    r.wait()
                    return NetworkRule(rule.name, rule.priority, rule.destination_address_prefix, rule.destination_port_range, rule.access, rule.description)
                return None
                if rule.priority < 1000 and rule.priority >= prio:
                    prio = rule.priority + 1
        newrule = SecurityRule(name=f'enableOutboundRule{prio}', description=description, protocol='Tcp', destination_address_prefix=cidr, destination_port_range=port, access='Allow', priority=prio, direction='Outbound', source_port_range='*', source_address_prefix='*')
        r = client.security_rules.begin_create_or_update(self.get_resource_group(), nsg.name, newrule.name, newrule)
        r.wait()
        return NetworkRule(newrule.name, newrule.priority, newrule.destination_address_prefix, newrule.destination_port_range, newrule.access, newrule.description)
    def get_batch_client(self) -> BatchServiceClient:
        '''
        Returns authenticated BatchServiceClient for manipulating and viewing Azure batch pools, jobs and data
        '''
        if self._client is None:
            (endpoint, name, key) = self.get_batch_account()
            class AzureIdentityCredentialAdapter(BasicTokenAuthentication):
                def __init__(self, credential=None, resource_id='https://management.azure.com/.default', **kwargs):
                    super(AzureIdentityCredentialAdapter, self).__init__(None)
                    self._policy = BearerTokenCredentialPolicy(credential, resource_id, **kwargs)
                def _make_request(self):
                    return PipelineRequest(
                        HttpRequest(
                            'AzureIdentityCredentialAdapter',
                            'https://fakeurl'
                        ),
                        PipelineContext(None)
                    )
                def set_token(self):
                    request = self._make_request()
                    self._policy.on_request(request)
                    token = request.http_request.headers["Authorization"].split(" ", 1)[1]
                    self.token = {"access_token": token}
                def signed_session(self, session=None):
                    self.set_token()
                    return super(AzureIdentityCredentialAdapter, self).signed_session(session)
            self._client = BatchServiceClient(AzureIdentityCredentialAdapter(self.get_credentials(True), 'https://batch.core.windows.net/'), 'https://' + endpoint)
        return self._client
    def update_hosts(self) -> None:
        '''
        Updates /etc/hosts so the service endpoint of the batch management instance is used (via its private IP) instead of its public IP (which is blocked by default)
        '''
        mgmtClient = NetworkManagementClient(self.get_credentials(True), self.get_subscription_id())
        endpoint =  next(mgmtClient.private_endpoints.list(resource_group_name=self.get_resource_group()))
        ip = endpoint.custom_dns_configs[0].ip_addresses[0]
        fqdn = endpoint.custom_dns_configs[0].fqdn
        if len(ip) > 0 and len(fqdn) > 0:
            with open('/etc/hosts', 'r+') as file:
                written = False
                lines = file.readlines()
                _ = file.seek(0)
                for i in lines:
                    if fqdn in i:
                        written = True
                        _ = file.write(ip + ' ' + fqdn)
                    else:
                        _ = file.write(i)
                if not written:
                    _ = file.write(ip + ' ' + fqdn)
                _ = file.truncate()
    def create_nextflow_scripts(self, out_nextflow_nf: str = 'nextflow.nf', out_nextflow_config: str = 'nextflow.config', out_nextflow_py: str = 'nextflow.py'):
        '''
        Creates three nextflow scripts for minimal working example of a nextflow run in the current directory. Can be used as starter to build further upon

        Requires the names of the three output files. Doesn't overwrite any files if they already exist
        '''
        if not os.path.isfile(out_nextflow_config):
            config = self.get_config()['azure']['batch']
            sa = self.get_storage_account()
            with open(out_nextflow_config, 'wt') as file:
                file.write(f"""
manifest {{
    name = "Azure Batch test pipeline"
    author = "RUMC"
    mainScript = "nextflow.nf"
    nextflowVersion = ">=21.04.0"
    version = "1.0.0"
}}

process {{
    executor = "azurebatch"
    withName: TEST {{
        queue="test_pool"
    }}
}}

azure {{
    storage {{
        accountName = "{sa[0]}"
        accountKey = "{sa[1]}"
    }}
    batch {{
        endpoint = "{config['endpoint']}"
        accountName = "{config['accountName']}"
        accountKey = "{config['accountKey']}"
        deletePoolsOnCompletion = true
        pools {{
            test_pool {{
                autoScale = false
            }}
        }}
    }}
}}  
""")
        if not os.path.isfile(out_nextflow_py):
            with open(out_nextflow_py, 'wt') as file:
                file.write(f"""#!/usr/bin/env python

import os
import subprocess
from azure.storage.blob import BlobServiceClient
from nextflowhelper import NextflowHelper

if not os.path.isdir('~/.nextflow'):
    print('Copying nextflow plugins')
    subprocess.check_call(['nextflowplugins'])

helper = NextflowHelper()
if os.geteuid() == 0:
    helper.update_hosts() # must be sudo here, but you only need to run this once
else:
    print('You may need to run helper.update_hosts() as sudo if the next command fails')

poolexists = False
for pool in helper.list_batch_pools():
    if pool.id == 'test_pool':
        poolexists = True
        print('Example pool already exists')
        break
if not poolexists:
    print('Creating example pool')
    helper.create_batch_pool('test_pool')

#helper.get_config() #use to create .config

print('Creating output container')
storageAccountDetails = helper.get_storage_account()
cnt = BlobServiceClient(f'https://{sa[0]}.blob.core.windows.net', credential=sa[1]).get_container_client('output-container')
if not cnt.exists():
    cnt.create_container()

print('Running command')
subprocess.check_call(['nextflow', 'run', '{out_nextflow_nf}', '-w', f'az://output-container/work'])

print('Cleaning up')
for pool in helper.list_batch_pools(): helper.delete_batch_pool(pool.id)

#if you are creating rules to open up, use this to disable them:
#for rule in helper.list_network_rules(): helper.delete_network_rule(rule.name)
""")
        if not os.path.isfile(out_nextflow_nf):
            with open(out_nextflow_nf, 'wt') as file:
                file.write("""#!/usr/bin/env nextflow
items = Channel.of(1,2,3,4,5)

process TEST {
    tag "\$x"
    container "ubuntu:20.04"

    input:
        val x from items

    output:
        path("\${x}.txt") into out_ch

    script:
    \"\"\"
    echo 'Hello World!' >> \${x}.txt
    \"\"\"
}
""")
        print('Written files in current working directory. Run the python script (python xxx.py) to start the nextflow process. Do not forget to open up network access to container repositories.')
    def get_config(self):
        '''
        Returns the Azure batch specific section of the nextflow config file as object.
        '''
        (endpoint, batchname, batchkey) = self.get_batch_account()
        (name, key) = self.get_storage_account()
        pools = self.list_batch_pools()
        poolobject = {}
        for pool in pools:
            poolobject[pool.id] = {
                'autoScale': False
            }
        return {
            'azure': {
                'storage': {
                    'accountName': name,
                    'accountKey': key
                },
                'batch': {
                    'endpoint': 'https://' + endpoint,
                    'accountName': batchname,
                    'accountKey': batchkey,
                    'pools': poolobject,
                    'copyToolInstallMode': 'node'
                }
            }
        }
    def get_batch_account(self) -> BatchManagementClient:
        '''
        Returns an instance of the BatchManagementClient using the VMs credentials
        '''
        mgmtClient = BatchManagementClient(self.get_credentials(True), self.get_subscription_id())
        batchAccount = next(x for x in mgmtClient.batch_account.list() if 'resourceGroups/dws-' in x.id)
        regexSearch = re.search("/resourceGroups/(.*?)/", batchAccount.id)
        rgName = regexSearch.groups()[0]
        keys = mgmtClient.batch_account.get_keys(rgName, batchAccount.name)
        return batchAccount.account_endpoint, batchAccount.name, keys.primary
    def get_storage_account(self) -> Tuple[str, str]:
        '''
        Returns a tuple of the storage account name and first storage account key which can be used to gain access to the workspace storage.
        '''
        mgmtClient = StorageManagementClient(self.get_credentials(True), self.get_subscription_id())
        workspaceStorage = next(x for x in mgmtClient.storage_accounts.list() if 'resourceGroups/dws-' in x.id)
        regexSearch = re.search("/resourceGroups/(.*?)/", workspaceStorage.id)
        rgName = regexSearch.groups()[0]
        keyresult = mgmtClient.storage_accounts.list_keys(rgName, workspaceStorage.name)
        return workspaceStorage.name, keyresult.keys[0].value
    def get_batch_subnetid(self) -> str:
        '''
        Returns the subnetid (resourceid) of teh subnet in which the batch nodes can/should be deployed to.
        Batch nodes can be deployed to outside this subnet, but then they won't have access to the workspace storage.

        '''
        mgmtClient = NetworkManagementClient(self.get_credentials(True), self.get_subscription_id())
        network = next(x for x in mgmtClient.virtual_networks.list_all() if 'resourceGroups/dws-' in x.id)
        return network.subnets[0].id
    def create_batch_pool(self, pool_id: str, display_name: str = '', vm_size: str = 'Standard_D2_v2', cpu_per_node: int = 4, node_agent_sku: str='batch.node.ubuntu 20.04', dedicatedNodes: Optional[int] = 1, spotNodes: Optional[int] = None, scalingFormula: Optional[str] = None, imageOffer: str='ubuntu-server-container', imagePublisher: str='microsoft-azure-batch', imageSku:str='20-04-lts', imageVersion: str='latest', wait: bool = True):
        '''
        Creates a Azure batch pool of one or more nodes on which to run jobs

        By default the pool size is fixed, but you cna enter a scalingFormula to enable autoscaling. If scalingFormula is set to 'Default', the default scalingFormula (see _DEFAULT_SCALING_FORMULA) provided by nextflow is used.
        '''
        (accountName, accountKey) = self.get_storage_account()
        cnt = BlobServiceClient(f'https://{accountName}.blob.core.windows.net', credential=accountKey).get_container_client('azcopy')
        if not cnt.exists():
            cnt.create_container()
        azcopyblob = BlobClient(f'https://{accountName}.blob.core.windows.net', 'azcopy', 'azcopy', credential=accountKey)
        if not azcopyblob.exists():
            scriptpath = f'{os.path.dirname(os.path.abspath(__file__))}/azcopy' if os.name == 'nt' else '/usr/local/bin/azcopy'
            with open(scriptpath, 'rb') as data:
                azcopyblob.upload_blob(data, blob_type="BlockBlob")
        sas = generate_blob_sas(account_name=accountName, container_name='azcopy', blob_name='azcopy', account_key=accountKey, permission=BlobSasPermissions(read=True), expiry=datetime.utcnow() + timedelta(days=31))
        azcopyurl = f'https://{accountName}.blob.core.windows.net/azcopy/azcopy?{sas}'
        batch_subnet_id = self.get_batch_subnetid()
        client = self.get_batch_client()
        x = client.pool.add(PoolAddParameter(
            id = pool_id,
            display_name = display_name,
            virtual_machine_configuration = VirtualMachineConfiguration(
                image_reference = ImageReference(publisher=imagePublisher, offer=imageOffer, sku=imageSku, version=imageVersion),
                node_agent_sku_id = node_agent_sku,
                container_configuration = ContainerConfiguration()),
            vm_size = vm_size,
            start_task = StartTask(user_identity=UserIdentity(auto_user=AutoUserSpecification(elevation_level='admin')), command_line=f'bash -c "mkdir -p \$AZ_BATCH_NODE_SHARED_DIR/bin/ && wget \'{azcopyurl}\' -O azcopy && chmod +x azcopy && cp azcopy \$AZ_BATCH_NODE_SHARED_DIR/bin/"'),
            auto_scale_formula = scalingFormula if scalingFormula != 'Default' else self._DEFAULT_SCALING_FORMULA,
            enable_auto_scale = len(scalingFormula) > 0 if scalingFormula is not None else False,
            target_dedicated_nodes = dedicatedNodes,
            target_low_priority_nodes = spotNodes,
            task_slots_per_node = cpu_per_node,
            network_configuration = NetworkConfiguration(subnet_id = batch_subnet_id)
            ))
        if wait:
            for _timeout in range(0, 60 * 15, 15):
                time.sleep(15)
                status = self.get_batch_pool_status(pool_id)
                if status.PoolStatus == 'active' and status.AllocationStatus == AllocationState.steady and all(status.NodeStatus[node] == 'idle' for node in status.NodeStatus):
                    return x
            raise Exception('Pool deployment timed out')
        return x
    def get_batch_pool_status(self, pool_id: str) -> PoolStatus:
        '''
        Returns pool deployment status and node state of the provided pool.
        '''
        client = self.get_batch_client()
        pool = client.pool.get(pool_id)
        ret = PoolStatus()
        ret.NodeStatus = {}
        ret.PoolStatus = pool.state
        ret.AllocationStatus = pool.allocation_state
        for node in client.compute_node.list(pool_id):
            ret.NodeStatus[node.id] = node.state
        return ret
    def list_image_types(self):
        '''
        Returns a list of all image types available to this batch account with known compatibility (docker enabled)
        '''
        client = self.get_batch_client()
        result = list()
        for i in client.account.list_supported_images():
            if i.capabilities is not None and 'DockerCompatible' in i.capabilities:
                result.append(i)
        return result
    def list_batch_pools(self) -> CloudPoolPaged:
        '''
        Returns a iterable list of pools currently active in the batch account
        '''
        client = self.get_batch_client()
        return client.pool.list()
    def delete_batch_pool(self, pool_id: str, wait: bool = True):
        '''
        Delete a specific batch pool
        '''
        client = self.get_batch_client()
        x = client.pool.delete(pool_id)
        if wait:
            for _timeout in range(0, 60 * 15, 15):
                time.sleep(15)
                #todo: will this return none?
                try:
                    client.pool.get(pool_id)
                except:
                    return x
        return x
EOF

################################
cat << EOF > /tmp/requirements.txt
adal==1.2.7
azure-batch==12.0.0
azure-common==1.1.28
azure-core==1.25.1
azure-identity==1.10.0
azure-mgmt-batch==16.2.0
azure-mgmt-containerregistry==10.0.0
azure-mgmt-core==1.3.2
azure-mgmt-network==21.0.1
azure-mgmt-resource==21.1.0
azure-mgmt-storage==20.1.0
azure-storage-blob==12.13.1
certifi==2022.6.15.1
cffi==1.15.1
charset-normalizer==2.1.1
cryptography==38.0.1
idna==3.3
isodate==0.6.1
msal==1.18.0
msal-extensions==1.0.0
msrest==0.7.1
msrestazure==0.6.4
oauthlib==3.2.0
portalocker==2.5.1
pycparser==2.21
PyJWT==2.4.0
python-dateutil==2.8.2
requests==2.28.1
requests-oauthlib==1.3.1
six==1.16.0
typing_extensions==4.3.0
urllib3==1.26.12
EOF
pip install -r /tmp/requirements.txt
rm /tmp/requirements.txt