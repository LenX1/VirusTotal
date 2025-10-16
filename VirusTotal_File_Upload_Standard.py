# https://docs.virustotal.com/reference/files-scan

import requests

url = "https://www.virustotal.com/api/v3/files"

files = { "file": ("InsertPathToFileHere", open("InsertPathToFileHere", "rb"), "File/Type") }
headers = {
    "accept": "application/json",
    "x-apikey": "InsertApiKeyHere"
}

response = requests.post(url, files=files, headers=headers)

print(response.text)
