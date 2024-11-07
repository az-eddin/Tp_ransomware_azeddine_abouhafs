from itertools import cycle

def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Applique l'opération XOR pour chiffrer ou déchiffrer des données en utilisant la clé fournie.
    """
    # Création d'une clé infinie pour correspondre à la longueur des données
    extended_key = cycle(key)
    # Association des paires de bytes entre les données et la clé
    paired_data = zip(data, extended_key)
    # Application du XOR sur chaque paire de bytes
    result = bytes(a ^ b for a, b in paired_data)
    return result

def xor_file(file_path: str, key: bytes) -> None:
    """
    Chiffre ou déchiffre un fichier en utilisant l'opération XOR avec la clé spécifiée.
    """
    # Lecture du fichier pour obtenir son contenu binaire
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Application de l'opération XOR sur le contenu
    encrypted_data = xor_encrypt_decrypt(file_data, key)

    # Écriture des données transformées dans le fichier
    with open(file_path, "wb") as file:
        file.write(encrypted_data)
