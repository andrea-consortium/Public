from flask import Flask, render_template, jsonify, request
from uuid import UUID
from azure.storage.blob import generate_container_sas, ContainerSasPermissions
import urllib.parse
import datetime
import requests
import re
import os
import xmltodict
import json

#"Database'
workspaces = {}
sourcesascache = {}

#load config.json
#{
#    "tenantkey": "tenant API key",
#    "repoStorage": {
#        "Account": "randomstorageaccount",
#        "AccountKey": "key for this storage account",
#        "Container": "databestaatni"
#    },
#    "workspaces": {
#        "dws-001-TEST": "worspacekey"
#    }
#}

with open('config.json') as json_file:
    config = json.load(json_file)

if 'workspaces' in config:
    for key in config['workspaces'].keys():
        workspaces[key] = {
            'key': config['workspaces'][key]
        }

app = Flask(__name__, template_folder=os.path.dirname(__file__))
app.config['TEMPLATES_AUTO_RELOAD'] = True

#show html file
@app.route('/')
def returnindex():
    return render_template("index.html")

#remove workspace key
@app.route('/workspaces/<workspaceName>', methods=['DELETE'])
def removeWorkspace(workspaceName: str):
    if workspaceName in workspaces:
        workspaces.pop(workspaceName)
        return '', 200
    return '',404

#add workspace key
@app.route('/workspaces', methods=['POST'])
def addWorkspace():
    workspace = request.get_json(force=True)
    if 'name' not in workspace or 'apiKey' not in workspace:
        return 'POST Expects object with name and apikey properties', 400
    if workspace['name'] in workspaces:
        return 'Workspace already added. If you want to update the key, please remove the old one first', 400
    try:
        uuid = UUID(workspace['apiKey'])
        if bool(re.compile("^dws-\d+-\w+$").search(workspace['name'])):
            x = requests.post(getUrl(workspace['name']), headers={
                'Api-Key': workspace['apiKey'],
                'Ocp-Apim-Subscription-Key': config['tenantkey']
            })
            if x.status_code != 200:
                return 'API key invalid', 400
            workspaces[workspace['name']] = {
                'key': workspace['apiKey']
            }
        else:
            return 'workspace name invalid', 400
    except Exception as e:
        return 'workspace name and/or key invalid', 400
    else:
        return jsonify(workspace)

@app.route('/workspaces')
def getWorkspaces():
    returned={}
    for key in workspaces.keys():
        returned[key] = workspaces[key]["key"]
    return jsonify(returned)

#create a upload container
@app.route('/workspaces/<workspaceName>/containers', methods=['POST'])
def createContainer(workspaceName: str):
    title = request.args.get('title', default='', type=str)
    containerName = '' if len(title) < 1 else urllib.parse.quote_plus(title)
    container = requests.post(f'{getUrl(workspaceName)}?title={containerName}', headers = getHeaders(workspaceName))
    jsoncontent = container.json()

    if 'sasUrls' not in workspaces[workspaceName]:
        workspaces[workspaceName]['sasUrls'] = { jsoncontent['identifier']: container.headers['location']}
    else:
        workspaces[workspaceName]['sasUrls'][jsoncontent['identifier']] = container.headers['location']

    return jsonify({
        jsoncontent['identifier'] : {
            'url': container.headers['location'],
            'title': jsoncontent['title'] or '<no title>'
        }
    })

#list all existing containers for a workspace
@app.route('/workspaces/<workspaceName>/containers')
def getWorkspaceContainers(workspaceName: str):
    headers = getHeaders(workspaceName)
    if headers is None:
        return 'Workspace not found', 404
    response = requests.get(getUrl(workspaceName), headers = headers)
    jsoncontent = response.json()
    retObj = {}
    for x in jsoncontent:
        retObj[x['identifier']] = {
            'title': x['title'] or '<no title>'
        }
    return jsonify(retObj)

#commit the container (i.e. move data from upload container to workspace)
@app.route('/workspaces/<workspaceName>/containers/<container>', methods=['PATCH'])
def commitContainer(workspaceName: str, container: str):
    requests.patch(f'{getUrl(workspaceName)}/{container}', headers = getHeaders(workspaceName))
    return 'Container is being committed', 200

#delete container / cancel upload
@app.route('/workspaces/<workspaceName>/containers/<container>', methods=['DELETE'])
def cancelContainer(workspaceName: str, container: str):
    requests.delete(f'{getUrl(workspaceName)}/{container}', headers = getHeaders(workspaceName))
    return '', 200

#get container files
@app.route('/workspaces/<workspaceName>/containers/<container>')
def getWorkspaceFiles(workspaceName: str, container:str):
    if workspaceName in workspaces:
        if 'sasUrls' in workspaces[workspaceName] and container in workspaces[workspaceName]['sasUrls']:
            url = workspaces[workspaceName]['sasUrls'][container]
            files = requests.get(f'{url}&restype=container&comp=list&include=copy', headers = {
                'x-ms-date': f'{datetime.datetime.now(datetime.timezone.utc)}'
            })
            return jsonify(toJson(files.content))
        else:
            return 'Unauthorized to read contents of '+container, 403
    else:
        return jsonify([])

#start upload
@app.route('/workspaces/<workspaceName>/containers/<container>', methods=['POST'])
def startCopy(workspaceName: str, container: str):
    url = None if workspaceName not in workspaces or 'sasUrls' not in workspaces[workspaceName] or container not in workspaces[workspaceName]['sasUrls'] else workspaces[workspaceName]['sasUrls'][container]
    if url is None:
        return 'Not authorized to access container', 403

    urlparts = url.split('?')
    postedfiles = request.get_json(force=True)
    sourceSas = getSourceSas()
    repoStorageAccount = config['repoStorage']['Account']
    repoStorageContainer = config['repoStorage']['Container']
    if 'files' in postedfiles:
        for file in postedfiles['files']:
            requests.put(f'{urlparts[0]}/{file}?{urlparts[1]}', headers = {
                'x-ms-copy-source': f'https://{repoStorageAccount}.blob.core.windows.net/{repoStorageContainer}/{file}?{sourceSas}',
                'x-ms-version': '2020-04-08',
                'x-ms-date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            })
    return '', 200

#get files
@app.route('/files')
def getFiles():
    storageAccount = config['repoStorage']['Account']
    container = config['repoStorage']['Container']
    sas = getSourceSas()
    files = requests.get(f'https://{storageAccount}.blob.core.windows.net/{container}?{sas}&restype=container&comp=list')
    return jsonify(toJson(files.content))

#xml response to list o' blobs
def toJson(response: bytes):
    dict_data = xmltodict.parse(response)
    result_dict = []
    blobs = dict_data['EnumerationResults']['Blobs']['Blob']
    
    for blob in (blobs if isinstance(blobs, list) else [blobs]):
        if 'CopyProgress' in blob['Properties']:
            copyProgress = blob['Properties']['CopyProgress']       
            p1 = float(copyProgress.split('/')[0])
            p2 = float(copyProgress.split('/')[1])

            copyPerc = '100%' if p1 == 0 or p2 == 0 else f'{p1 / p2 * 100:.0f}%'
        else:
            copyPerc = '100%'

        result_dict.append({
            'name': blob['Name'],
            'size': blob['Properties']['Content-Length'],
            'copystate': 'success' if 'CopyStatus' not in blob['Properties'] else blob['Properties']['CopyStatus'],
            'copyprogress': copyPerc
        })
    return result_dict

def getUrl(workspaceName: str):
    return f'https://andreanl-api-management.azure-api.net/v1/api/workspace/{workspaceName}/files/containers'
    
def getHeaders(workspace: str):
    if workspace not in workspaces:
        return None
    return {
        'Api-Key': workspaces[workspace]['key'],
        'Ocp-Apim-Subscription-Key': config['tenantkey']
    }

def getSourceSas():
    if 'cache' not in sourcesascache:
        repoStorageAccount = config['repoStorage']['Account']
        repoStorageAccountKey = config['repoStorage']['AccountKey']
        repoStorageAccountContainer = config['repoStorage']['Container']
        sourcesascache['cache'] = generate_container_sas(repoStorageAccount, repoStorageAccountContainer, repoStorageAccountKey, permission=ContainerSasPermissions.from_string("rl"), expiry=datetime.datetime.utcnow() + datetime.timedelta(days=7))
    return sourcesascache['cache']

app.run(host='0.0.0.0', port=81)