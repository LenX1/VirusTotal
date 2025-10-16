
import requests
import os
import datetime


Api_Key = "InsertApiKeyHere"

file_type = "multipart/form-data"
url = "https://www.virustotal.com/api/v3/files"

timestamp_csv = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')

for file in (os.listdir()[:]):  # [Start:End]
    files = { "file": (f"{file}", open(f"{file}", "rb"), f"{file_type}") }
    headers = {
        "accept": "application/json",
        "x-apikey": f"{Api_Key}",
    }
    response = requests.post(url, files=files, headers=headers)
    timestamp_file = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')

    with open(f'VirusTotal-Upload_{timestamp_csv}.csv', 'a') as f:
        f.write(f'{response.text} ,{timestamp_file}\n')




