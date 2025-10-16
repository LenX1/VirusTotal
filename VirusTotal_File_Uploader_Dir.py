
import requests
import os
import datetime
import hashlib


Api_Key = ""  # InsertApiKeyHere
path = ''  #  InsertPathToFileHere

file_type = "multipart/form-data"
url = "https://www.virustotal.com/api/v3/files"

timestamp_csv = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
buffer_size = 65536

for file in (os.listdir(path)[:]):  # [Start:End]

    if os.path.isdir(path+file):
        continue
    elif file.endswith(".exe"):  #  check for specific file endings
        continue

    files = { "file": (f"{file}", open(f"{path+file}", "rb"), f"{file_type}") }
    headers = {
        "accept": "application/json",
        "x-apikey": f"{Api_Key}",
    }
    response = requests.post(url, files=files, headers=headers)
    timestamp_file = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')

    sha256 = hashlib.sha256()
    with open(path+file, 'rb') as f:
        while True:
            data = f.read(buffer_size)
            if not data:
                break
            sha256.update(data)
    hash256 = format(sha256.hexdigest())

    with open(f'VirusTotal-Upload_{timestamp_csv}.csv', 'a') as f:
        f.write(f'{hash256}, {timestamp_file}, {response.text}\n')



