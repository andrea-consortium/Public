#!/usr/bin/python3

import threading
import base64
import sys
import time
import queue
import os
import io
import datetime

from urllib import request
from urllib import parse

# parameters you can predefine or update later
############
paths = list()
block_size = 4 * 1024 * 1024 #default 4Mb
single_upload_size = 8 * 1024 * 1024 
workspace_apikey = ''
subscription_apikey = ''
workspace_name = ''
max_concurrency = 10
api = 'https://andreanl-api-management.azure-api.net/v1/api'
pause = False
###########

filequeue = queue.Queue()
container_uri: str
sas_token: str
semaphore: threading.Semaphore
uploadsize_lock = threading.Lock()
uploadsize = 0
donefiles = 0
threadCancellationflag = False
uploadfiles_blockspending = dict()

class todofile:
    file_stream: io.BufferedReader = None
    file_size: int
    file_chunks: int = 0
    blob_name: str
    full_name: str
    def __init__(self, blob_name: str, full_name: str):
        self.blob_name = parse.quote(blob_name.replace('\\', '/'))
        self.full_name = full_name
        self.file_size = os.path.getsize(full_name)

def get_url():
    global api,workspace_name
    return f'{api}/workspace/{workspace_name}/files/containers'

def get_headers():
    global subscription_apikey, workspace_apikey
    return {
        'Api-Key': workspace_apikey,
        'Ocp-Apim-Subscription-Key': subscription_apikey
    }

def create_upload_container():
    global container_uri, sas_token
    container = request.urlopen(request.Request(get_url(), headers=get_headers(), method='POST'))
    if container.status < 200 or container.status > 299:
        print(f"ERROR - Failed to create container: HTTP{container.status}: {container.read()}")
        return False
    path_parts = container.headers.get('location').split('?')
    container_uri = path_parts[0]
    sas_token = '?' + path_parts[1]
    return True

def commit_upload_container():
    global container_uri
    containername = container_uri.split('/')[3]
    resp = request.urlopen(request.Request(f'{get_url()}/{containername}', headers=get_headers(), method='PATCH'))
    if resp.status < 200 or resp.status > 220:
        print(f"ERROR - Failed to commit container: HTTP{resp.status}: {resp.read()}")

def cancel_upload_container():
    global container_uri
    containername = container_uri.split('/')[3]
    resp = request.urlopen(request.Request(f'{get_url()}/{containername}', headers=get_headers(), method='DELETE'))
    if resp.status < 200 or resp.status > 299:
        print(f"ERROR - Failed to cancel container: HTTP{resp.status}: {resp.read()}")

def upload_file_single(blobname: str, file: io.BufferedReader) -> bool:
    global container_uri, sas_token
    chunk = file.read()
    resp = request.urlopen(request.Request(f"{container_uri}/{blobname}{sas_token}", chunk, headers={
        'x-ms-version': '2020-04-08',
        'x-ms-blob-type': 'BlockBlob',
        'x-ms-date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    }, method='PUT'))
    if resp.status < 200 or resp.status > 220:
        raise Exception(f"HTTP{resp.status}: {resp.read()}")

def upload_file_chunk(blobname: str, blocknumber: int, chunk: bytes) -> int:
    global container_uri, sas_token
    block_id = base64.b64encode(f"block{blocknumber:06d}".encode('utf8')).decode('utf8')
    resp = request.urlopen(request.Request(f"{container_uri}/{blobname}{sas_token}&comp=block&blockid={block_id}", chunk, headers={
        'x-ms-version': '2020-04-08',
        'x-ms-date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    }, method='PUT'))
    if resp.status < 200 or resp.status > 220:
        raise Exception(f"HTTP{resp.status}: {resp.read()}")

def finalise_chunked_file(blobname: str, chunks: int) -> bool:
    global container_uri, sas_token
    contents = '<?xml version="1.0" encoding="utf-8"?><BlockList>'
    for chunk in range(chunks):
        contents += '\r\n<Uncommitted>' + base64.b64encode(f"block{chunk:06d}".encode('utf8')).decode('utf8') + '</Uncommitted>'
    contents += '</BlockList>'
    resp = request.urlopen(request.Request(f"{container_uri}/{blobname}{sas_token}&comp=blocklist", contents.encode('utf8'), headers={
        'Content-Type': 'text/plain; charset=UTF-8',
        'x-ms-version': '2020-04-08',
        'x-ms-date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    }, method='PUT'))
    if resp.status < 200 or resp.status > 220:
        raise Exception(f"HTTP{resp.status}: {resp.read()}")

#get all files passed to us
def get_files(paths: list):
    global filequeue
    for item in paths:
        if os.path.isfile(item):
            print(f"Found file {item} to upload")
            filequeue.put(todofile(os.path.basename(item), os.path.abspath(item)))
        elif os.path.isdir(item):
            print(f"Found directory {item} to upload")
            baselen = len(item) + 1
            for dp, _dn, filenames in os.walk(item):
                for filename in filenames:
                    filequeue.put(todofile(os.path.join(dp, filename)[baselen:], os.path.abspath(os.path.join(dp, filename))))
        else:
            print(f"ERROR - {item} could not be found")

def convert_bytes(input: float, fmt: str) -> str:
    for i in range(5):
        if input < 1023 or i == 4:
            return fmt.format(input, ['bytes', 'Kb', 'Mb', 'Gb', 'Tb'][i])
        else:
            input /= 1024

def print_progress():
    global uploadsize, uploadtime, donefiles, totalfiles, threadCancellationflag
    strfmt = "Uploading [{0:20}] {1:"+str(len(str(totalfiles)))+"}/{2} {3:17} total: {4:10}"
    while totalfiles > 0 and not threadCancellationflag:
        x = int(20 * donefiles / totalfiles)
        spent = time.time() - uploadtime
        speed = 0 if spent == 0 else uploadsize / spent
        b1 = convert_bytes(speed, '{0:9.3f} {1}/s')
        b2 = convert_bytes(float(uploadsize), '{0:9.2f} {1:5}')
        print(strfmt.format('#'*x, donefiles, totalfiles, b1, b2), end='\r', flush=True)
        time.sleep(1)

class semaphorelock():
    global threadCancellationflag
    hasSemaphore = False
    semaphore: threading.Semaphore
    def __init__(self, semaphore: threading.Semaphore):
        self.semaphore = semaphore
    def __enter__(self):
        while not threadCancellationflag:
            self.hasSemaphore = semaphore.acquire(timeout=1)
            if self.hasSemaphore or threadCancellationflag:
                break
            time.sleep(1)
    def __exit__(self, type, value, traceback):
        if self.hasSemaphore:
            semaphore.release()

def upload_file_thread():
    global uploadsize, donefiles, filequeue, threadCancellationflag, single_upload_size, uploadfiles_blockspending
    while not threadCancellationflag:
        try:
            file: todofile = filequeue.get(block=True, timeout=2+(2 * len(uploadfiles_blockspending)))
            if file.file_size <= single_upload_size:
                with semaphorelock(semaphore):
                    try:
                        if threadCancellationflag:
                            break
                        with open(file.full_name, mode='rb') as filestream:
                            upload_file_single(file.blob_name, filestream)
                        with uploadsize_lock:
                            uploadsize += file.file_size
                            donefiles += 1
                    except Exception as e:
                        print (f"\r\nERROR - Uploading file {file.blob_name}: {e}")
            else:
                with uploadsize_lock:
                    if uploadfiles_blockspending.get(file.full_name, 0) == -1:
                        continue
                try:
                    if file.file_stream is None:
                        file.file_stream = open(file.full_name, mode='rb')
                        with uploadsize_lock:
                            uploadfiles_blockspending[file.full_name] = 1
                    with semaphorelock(semaphore):
                        if threadCancellationflag:
                            break
                        try:
                            chunk = file.file_stream.read(block_size)
                            chunkid = file.file_chunks
                            done = len(file.file_stream.peek()) == 0
                            if not done:
                                with uploadsize_lock:
                                    uploadfiles_blockspending[file.full_name] += 1
                                    file.file_chunks += 1
                                    filequeue.put(file)
                            try:
                                upload_file_chunk(file.blob_name, chunkid, chunk)
                            except Exception as e:
                                print (f"\r\nERROR - Uploading file {file.blob_name} chunk #{chunkid}: {e}")
                                with uploadsize_lock:
                                    uploadfiles_blockspending[file.full_name] = -1
                                    try:
                                        file.file_stream.close()
                                    except:
                                        pass
                                continue
                            with uploadsize_lock:
                                uploadsize += len(chunk)
                                uploadfiles_blockspending[file.full_name] -= 1
                                alldone = uploadfiles_blockspending[file.full_name] < 1
                                if alldone:
                                    uploadfiles_blockspending.pop(file.full_name)
                            if alldone:
                                try:
                                    file.file_stream.close()
                                except:
                                    pass
                                finalise_chunked_file(file.blob_name, file.file_chunks + 1)
                                with uploadsize_lock:
                                    donefiles += 1
                        except Exception as e:
                            print(f"\r\nERROR - Committing file {file.blob_name}: {e}")
                except Exception as e:
                    print(f"\r\nERROR - Uploading file {file.blob_name}: {e}")
        except:
            break

if __name__ == "__main__":
    i = 1
    argc = len(sys.argv)
    while i < argc:
        try:
            if sys.argv[i] == '--api' and i < argc - 1:
                api = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == '--workspace-name' and i < argc - 1:
                workspace_name = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == '--subscription-apikey' and i < argc - 1:
                subscription_apikey = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == '--workspace-apikey' and i < argc - 1:
                workspace_apikey = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == '--max-concurrency' and i < argc - 1:
                max_concurrency = int(sys.argv[i + 1])
                i += 2
            elif sys.argv[i] == '--block-size' and i < argc - 1:
                block_size = int(sys.argv[i + 1])
                i += 2
            elif sys.argv[i] == '--single-upload-size' and i < argc - 1:
                single_upload_size = int(sys.argv[i + 1])
                i += 2
            elif sys.argv[i] == '--pause':
                i += 1
                pause = True
            elif sys.argv[i].startswith('--'):
                print(f"ERROR - Unknown argument '{sys.argv[i]}'")
                quit(-1)
            else:           
                paths.append(sys.argv[i])
                i += 1
        except ValueError as e:
            print(f"ERROR - {sys.argv[i]} '{sys.argv[i + 1]}' is not a number")
            quit(-1)
    semaphore = threading.Semaphore(max(1, min(max_concurrency, 30)))
    #start routime
    print(f"Starting upload to {workspace_name}")
    print('Gathering files ...')
    get_files(paths)
    totalfiles = filequeue.qsize()
    print(f"{totalfiles} files found")
    if totalfiles == 0:
        print('ERROR - Nothing to do, quitting')
        if pause:
            _ = input("Press Enter to continue...")
        quit(-1)
    print('Creating container ...')
    if not create_upload_container():
        if pause:
            _ = input("Press Enter to continue...")
        quit(-1)
    print(f"SAS-token for container: {container_uri}{sas_token}")
    uploadThreads = list()
    uploadtime = time.time()
    print('Starting upload')
    progressThread = threading.Thread(target = print_progress, daemon=True)
    progressThread.start()
    for i in range(max(1, min(max_concurrency, 1000))):
        thread = threading.Thread(target = upload_file_thread, daemon=True)
        uploadThreads.append(thread)
        thread.start()
    try:
        for thread in uploadThreads:
            while thread.is_alive():
                thread.join(1)
        threadCancellationflag = True
        progressThread.join()
        print('\r\nCommitting upload')
        commit_upload_container()
        print('SUCCESS - Upload completed!')
        if pause:
            _ = input("Press Enter to continue...")
    except (KeyboardInterrupt, SystemExit):
        threadCancellationflag = True
        progressThread.join()
        print('WARNING - Cancelling running uploads')
        for thread in uploadThreads:
            while thread.is_alive():
                thread.join(1)
        print('Cancelling upload container ...')
        cancel_upload_container()
        if pause:
            _ = input("Press Enter to continue...")
        quit(-1)
    finally:
        threadCancellationflag = True
        if progressThread.is_alive():
            progressThread.join()
