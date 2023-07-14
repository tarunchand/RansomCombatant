from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from config import Config
import os


def upload_file_to_drive(file_path, folder_id):
    file_drive = drive.CreateFile({'title': os.path.basename(file_path),
                                   'parents': [{'id': folder_id}]})
    file_drive.Upload()


def upload_folder_to_drive(local_folder, folder_id):
    for root, dirs, files in os.walk(local_folder):
        for filename in files:
            filepath = os.path.join(root, filename)
            upload_file_to_drive(filepath, folder_id)
        for dir_name in dirs:
            folder_path = os.path.join(root, dir_name)
            folder_drive = drive.CreateFile({'title': os.path.basename(folder_path),
                                             'parents': [{'id': folder_id}],
                                             'mimeType': 'application/vnd.google-apps.folder'})
            folder_drive.Upload()
            sub_folder_id = folder_drive.get('id')
            upload_folder_to_drive(folder_path, sub_folder_id)


if __name__ == '__main__':
    auth = GoogleAuth()
    auth.DEFAULT_SETTINGS['client_config_file'] = Config.GOOGLE_DRIVE_CLIENT_SECRETS_JSON_FILE
    auth.LocalWebserverAuth()
    drive = GoogleDrive(auth)
    print('[+] Backing up : ', Config.SAFE_GUARD_FOLDER)
    upload_folder_to_drive(Config.SAFE_GUARD_FOLDER, Config.GOOGLE_DRIVE_TARGET_FOLDER_ID)
