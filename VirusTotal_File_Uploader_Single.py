
import requests

Api_Key = "InsertApiKeyHere"
file = "InsertPathToFileHere"
file_type = "File/Type"

url = "https://www.virustotal.com/api/v3/files"

files = { "file": (f"{file}", open(f"{file}", "rb"), f"{file_type}") }

headers = {
    "accept": "application/json",
    "x-apikey": f"{Api_Key}",
}

response = requests.post(url, files=files, headers=headers)

print(response.text)
