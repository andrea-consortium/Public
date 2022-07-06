# anDREa API management example

This project contains example code to demonstrate the use of the API management layer around data 
uploads for anDREa workspaces. It is a simple emulation of a local data repository (in this code represented by files hosted in a Azure storage account) and a workspace upload mechanism. In real applications, the local data repository can be any data source the code has access to, including but not limited to a local fileshare, upload input or any form of cloudstorage.

The project consists of a single API written in Python (Flask) hosting the various endpoints as well as serving the files needed to display the website itself.

The API is designed to be simple to interpret, so few libraries are used and where possible REST calls are used to show how to work with the API endpoints.
The code is not production ready, it is purely meant for ***demos and educational purposes***.

> #"Database'  
> workspaces = {}  
> sourcesascache = {}

The database of the demo project consists of two global variables, one listing the workspaces, their keys, and cached container SAS-urls, and one caching the SAS-url for accessing the data repository.
Naturally, these variables will be cleared when the server is restarted. To store such data between server sessions, read/write them to a (temporary) file or database.

Languages used:
1. Python (Flask)
2. Javascript (vanilla)
3. HTML (+bootstrap)

## Configure
To configure the API edit the config.json file. Its structure is simple and requires the API Key (Tenant Key) in the form of a uuid to be preconfigured. An anDREa admin can generate such a key for you.
Optionally, you can preconfigure one or more workspaces with corresponding API key in the config file, this can be usefull for demoing.
As the demo project relies on a storage account to demonstrate a local repository, storage account details need to be added here too.

## How to run
First install the requirements.txt, i.e.

> Pip -r requirements.txt

then to start the server, simply execute the python script 
> Python server.py

Observe the url in the output. Generally, the url is http://[localhost]:81 or something similar.  Direct your browser to there and you can start.

This code can easily be hosted in a docker container or any webserver capable of hosting Python, though again this code is not production ready and should not be hosted on any publically accessible location unsupervised.

## How to use
First, select a workspace in the 'target workspace' input - if none exist, you can create a new workspace key by selecting '[New workspace]' and entering the workspace name and key generated from the portal at https://mydre.org. Use the 'delete key' button to delete existing keys, if desired. THe list of workspaces is pre-populated using input from the config.json file.

Next, select a target upload container (aka upload package). Here, too, you can select an existing container or create a new one (with optional title). Mind that due to absense of required API endpoint, you are not authorized to view the contents of any container listed here which doesn't have a corresponding cached url in the API - i.e. you can only view the contents of containers which have been created in the current server session. You can choose to delete existing containers or commit (upload their contents to the workspace) with the button at the bottom.

Below, you will find on teh left a list of files in the data repository, and on the right a list of files in teh currently selected upload container. Select one or more (hold ctrl) files on the left and click the 'upload' button to copy them to the upload container. In the example code both are storage accounts, so this should go pretty fast. Once all files are uploaded, hit the commit button to start the upload process to the workspace.
There is no indication or progress available to show commit has started or is finished - you will see it is finished once the files appear in the workspace or the container disappears from the list of containers after a page refresh (F5).
