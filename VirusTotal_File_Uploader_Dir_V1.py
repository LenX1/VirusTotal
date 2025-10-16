
import requests
import os

Api_Key = "InsertApiKeyHere"

file_type = "multipart/form-data"
url = "https://www.virustotal.com/api/v3/files"

for file in (os.listdir()[:]):
    files = { "file": (f"{file}", open(f"{file}", "rb"), f"{file_type}") }
    headers = {
        "accept": "application/json",
        "x-apikey": f"{Api_Key}",
    }
    response = requests.post(url, files=files, headers=headers)
    print(response.text)
