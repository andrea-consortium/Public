### files for azure batch in anDREa workspaces
The files here enable users to run azure batch in their workspace using nextflow.
Azure batch is a way to manage tasks accross many VMs, far surpassing the limits of a single workspace. Nextflow is a task scheduler that can be configured to run via Azure batch, giving users the possibilty to run tasks over hundreds or thousands of VMs.

There are two limitations:
- Access to internet/location of batch container repositories needs to be managed by the user. The headnode, when installed using the script in this repository, will have some handy tools to do so.
Completely removing internet access is only possible if user is willing to host their own container repository inside the workspace or batch network, which can be fairly costly relative to the cost of a small batch.

- Access to public storage accounts cannot be disabled due to a dependency on (fairly random) azure storage access built into azure batch. Untill microsoft fixes this, it is not possible to limit access only to the workspace stsorage account.

## Technical design
The setbatch script will install/configure the following resources
- vnet (with 'default' subnet to contain batch nodes)
- vnet acces rule for this vnet will be added to allow batch nodes to access the workspace fileshare
- the vm designated as headnode will be granted permissions to read and modify several resources in the workspace resource group using a custom 'Dre batch manager' role. In addition, the VM will be granted 'Virtual Machine contributor' to the batch vnet and 'contributor' to the batch management interface.
- Dre Batch Manager Azure role will be installed on the current subscription if it does not already exist
- DisablePublicBatchAccountAccess Azure policy will be installed and applied to the workspace to disable public access to the batch interface (i.e. blocking acecss from the Azure portal).
- A private endpoint will be installed in the workspace subnet to allow access to the batch management interface (requires one IP-address to be free in the workspace subnet)
- A nsg will be added to control access to/from the batch subnet. The nsg's name will start with a 'z' so avoid breaking down the anDREa web portal, which assuems the first nsg (alphabetally) in a workspace is the workspace nsg.

## Costs
Azure batch itself has no costs, though in order to secure the batch account a private endpoint is required (à ~EUR100/year). These costs will bne uncurred for as long as the batch account is installed.
Costs for compute and storage are carried by the workspace itself, and restricted the same way other VMs in a workspace are restricted. With azure batch it is fairly easy to go over budget though, and at the moment no measures are in place to limit spending when a cap has been reached.

## Using azure batch
The batch account will be scripted such that it cannot be accessed from outside the workspace network. the endpoint can be reached via the private IP address of the private endpoint from any VM in the workspace. One of the VMs in the workspace, the headnode, is a linux VM that runs the nextflow process to hand out jobs to the batch nodes. Additionally, access to the outside world and everything related to the batch account can be painlessly managed from within this VM using the provided python module.

# enable/install azure batch
```
Set-WorkspaceBatch -SubscriptionID $SubscriptionID -Workspace $workspace
```
optionally, pass the resource name of the headnode so it will recieve required Azure permissions for managing the batch account and nodes
The script has to be run by a user with Owner rights on the subscription. As the script must install an azure rule definition, the script may fail if the role is installed in subscriptions on which the user does not have access rights. In that case, the script has to be run by someone with more rights, such as a global admin.
   
# Remove azure batch from workspace
'''
Set-WorkspaceBatch -SubscriptionID $SubscriptionID -Workspace $workspace -Remove
'''
pass the resource name of the headnode so it will be removed from Azure permissions. Again, the script must be run by a user with Owner permissions.

# Prepare VM
The headnode (which should run nextflow) should be based on Ubuntu. Getting this to work in Centos is annoyingly difficult so not recommended.
Run the vm.sh script to install the required packages and python scripts. While this script is running, internet access is required. Once the script is done, internet access can be stopped.
It is possible to bake an image of the VM after the script has been installed, so it can be reused as a nextflow headnode in the same or other workspaces; the VM still needs the access rights as instaleld by the Set-WorkspaceBatch function though.

# To run the batch
The install script installs a Python package called nextflowHelper. You can get some example scripts to get you going fast using the following python code/commands:

```
from nextflowhelper import NextflowHelper
helper = NextflowHelper()
helper.create_nextflow_scripts()
```

After running this code you will find example nextflow scripts and a python starter script. The script can be used to validate the nextflow config (it is ready to go as is), otherwise you can edit it and modify as needed.
using dir() and help() on the helper object you can examin the other functionality exposed this way, for example:
* creating/listing/deleting batch pools (as nextflow does not support azure pools bound to vnets, you must use the helper to manage batch pools)
* creating/listing/deleting network rules (the set of rules for the batch network will be different from those of teh workspace, so the web interface of your workspace cannot be used to control the network access of your batch network).
fetching python clients for azure batch and the workspace storage account

to manage the network rules, you need to log in using your mydre.org account. the script will ask you to go to microsoft.com/devicelogin on a computer with internet (so not a anDREa machine) and copy the displayed code there. Once you've logged in, the script will continue. By default, the batch vnet has no external access. In normal circumstances, only access to a container repository is required.

At the moment of writing, this setup is not compatible with anDREa's solution for domain whitelisting. Only static ip addresses can be whitelisted or internet as a whole.