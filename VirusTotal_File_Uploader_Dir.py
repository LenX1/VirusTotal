
import requests
import os
import datetime
import hashlib
import time


def get_upload_status_daily(api_key):
    date_today = time.strftime("%Y%m%d")
    url_api_usage = f"https://www.virustotal.com/api/v3/users/{api_key}/api_usage?start_date={date_today}&end_date={date_today}"
    headers_api_usage = {
        "accept": "application/json",
        "x-apikey": f"{api_key}"
    }

    try:
        response_api_usage = requests.get(url_api_usage, headers=headers_api_usage)
        api_usage_daily = int(response_api_usage.text.split()[9][:-3])
        return api_usage_daily
    except error:
        return 0


def check_upload_limit(counter, limit):
    if counter >= limit:
        print("Daily limit exceeded")
        exit()
    else:
        counter += 1
        return counter


def upload_file(path_file, file_file, api_key):
    file_type = "multipart/form-data"
    url_upload = "https://www.virustotal.com/api/v3/files"
    files_upload = { "file": (f"{file_file}", open(f"{path_file+file_file}", "rb"), f"{file_type}") }
    headers_upload = {
        "accept": "application/json",
        "x-apikey": f"{api_key}",
    }
    response = requests.post(url_upload, files=files_upload, headers=headers_upload)
    return response


def get_file_hash(path_file, file_file):
    buffer_size = 65536  # 64 kb
    sha256 = hashlib.sha256()
    with open(path_file+file_file, 'rb') as ff:
        while True:
            data = ff.read(buffer_size)
            if not data:
                break
            sha256.update(data)
    hashed= format(sha256.hexdigest())
    return hashed


API_KEY = ""  # InsertApiKeyHere
path = ''  #  InsertPathToFileHere

index_start = 0
upload_limit_daily = 500
upload_delay = 0.25

api_usage_status = get_upload_status_daily(API_KEY)
timestamp_csv = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')

for file in (os.listdir(path)[index_start:]):  # [Start:End]

    api_usage_status = check_upload_limit(api_usage_status, upload_limit_daily)

    #  check for specific file endings
    if os.path.isdir(path+file):
        continue
    elif file.endswith(".exe"):
        continue

    upload_response = upload_file(path, file, API_KEY)

    file_hash = get_file_hash(path, file)

    timestamp_file = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')  # ?
    with open(f'VirusTotal-Upload_{timestamp_csv}.csv', 'a') as f:
        f.write(f'{file_hash}, {timestamp_file}, {upload_response.text}\n')

    print('{} : {} {}'.format(api_usage_status, path ,file))
    time.sleep(upload_delay)

