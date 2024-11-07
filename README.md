1)L'algorithme utilisé est le XOR, il utilise l'opération XOR entre les données et  la clé. Cet algorithme n’est pas robuste car il est réversible si on connait une partie du texte en clair ou si la clé est répétée, donc il est facilement cassable.

2)HMAC assure l'intégrité et l'authentification

3)Vérifier que le fichier token.bin n'existe pas déjà permet d’éviter la génération de plusieurs tokens pour la même instance de ransomware, ce qui compliquerait le processus de déchiffrement. Si un token existant est écrasé, il serait impossible de retrouver la clé de déchiffrement correcte, rendant ainsi le déchiffrement des fichiers chiffrés impossible pour la victime et annulant l’effet recherché de la rançon.

4)Pour vérifier que la clé est correcte, on dérive la clé qui permet de générer une clé de déchiffrement à partir du sel et de la clé de la victime. Ensuite, on compare cette clé dérivée avec la clé de chiffrement d’origine. Si elles correspondent, alors la clé fournie est valide pour déchiffrer les données.
