# Secure FTP Over UDP : Documentation

## Généralités

Le serveur écoute sur le port UDP 4445. Il est capable de traiter des messages allant jusqu'à 2048 octets. Au-delà, un message
d'erreur sera retourné.

En raison des particularités d'UDP, il est possible que des paquets soient ignorés par le serveur, ou que le contenu du paquet soit altéré en transit.

Un compte invité est utilisable pour vos tests :
- Identifiant = `GUEST_USER`
- Mot de passe = `GUEST_PASSWORD`

Le troisième et dernier flag est situé dans un sous dossier de `/opt/` sur le serveur.

## Structure d'un paquet 

Un paquet est composé de 4 sections :

### Entête

L'entête est composé de deux octets. 

Les 14 bits les plus significatifs correspondent à l'ID du paquet. 
Les 2 bits les moins significatifs correspondent à la taille en octet de la section `taille`.

### Taille

La section taille a une longueur variable de 1 à 3 octets. Elle définit la longueur de la section `contenu` en octets.

### Contenu

Le contenu du paquet. Celui-ci est spécifique à chaque paquet.


### CRC32

Somme de contrôle stockée sur 4 octets permettant de détecter une éventuelle modification du paquet pendant le transit.

L'algorithme utilisé est le même que celui présent dans Java (`java.util.zip.CRC32`).

La somme est calculée avec la concaténation des sections entête, taille et contenu.

## Protocole

Le protocole est structuré sous forme de **messages**. Chaque message a son identifiant et son contenu qui lui est propre. Le contenu de chaque message sera détaillé plus loin dans ce document.

Chaque message que vous envoyé peut être répondu par un message `ErrorMessage` contenant un code d'erreur. Vous devez vérifier que chaque message reçu n'est pas un message d'erreur avant de le traiter.

Pour communiquer avec ce serveur, il est nécessaire de suivre les étapes suivantes dans l'ordre :

* Etablissement d'une session :
    - Envoi d'un message `ConnectMessage`. Ce message doit avoir la chaîne de caractère `CONNECT` dans son attribut `data`.
    - Le serveur répondra à ce message en envoyant une réponse `ConnectReply` contenant votre identifiant de session et le premier flag.
* Authentification :
    - Envoi d'un message `RsaKeyMessage` avec comme argument `sessionId` votre identifiant de session.
    - Le serveur vous répondra avec la réponse `RsaKeyReply` contenant sa clé publique RSA (`servPubKey`). Cette clé est chiffrée avec l'algorithme XOR et la clé `ThisIsNotSoSecretPleaseChangeIt`, puis encodée en Base64.
    - Envoi d'un message `SessionKeyMessage`. Ce message contient votre identifiant de session et une clé AES 256 bits (algorithme `AES/CBC/PKCS5Padding`) que vous avez générée. Cette clé doit être chiffrée avec `servPubKey` et encodée en Base64.
    - Le serveur vous répondra avec la réponse `SessionKeyReply`. Ce message contient un sel de 10 octets sous forme d'un tableau d'octet chiffré avec votre clé AES encodé en Base64.
    - Envoi d'un message `AuthMessage`. Ce message contient :
        - Votre identifiant de session ;
        - Le sel chiffré avec la clé AES encodé en Base64 ;
        - Votre identifiant chiffré avec la clé AES encodé en Base64 ;
        - Votre mot de passe chiffré avec la clé AES encodé en Base64.
    - Le serveur répondra avec une réponse `AuthReply` contenant le message `AUTH_OK` si l'authentification a réussi et le deuxième flag.
* Utilisation :
    * Envoi d'un message `GetFilesMessage` pour lister les fichiers d'un répertoire. Ce message contient votre identifiant de session et le chemin à lister chiffré avec votre clé AES et encodé en Base64.
        - Le serveur répondra avec la réponse `GetFilesReply` qui contient les noms des fichiers du répertoire sous forme d'un tableau de chaîne de caractère chiffré avec votre clé AES et encodé en Base64.
    * Envoi d'un message `GetFileMessage` pour récupérer le contenu d'un fichier. Ce message contient votre identifiant de session et le chemin du fichier à récupérer chiffré avec votre clé AES et encodé en Base64.
        - Le serveur répondra avec la réponse `GetFileReply` qui contient le contenu du fichier chiffré avec votre clé AES et encodé en Base64.
    
## Format de sérialisation

* Les chaînes de caractères et les tableaux 'simples' sont sérialisés de la forme suivante :
    - 2 octets contenant la longueur de la chaîne ou du tableau.
    - La chaine ou le tableau.
* Un tableau de chaine de caractère est sérialisé de la forme suivante : 
    * Le contenu du tableau est concaténé à la suite avec le caractère NULL (`\0`) comme délimiteur.
    * Le résultat de la concaténation est traîté comme une chaîne de caractère et est sérialisé comme détaillé plus haut.

## Encodage des chaînes de caractères

Les chaînes de caractères sont encodées en UTF-8.

## Chiffrement AES

Toutes les messages chiffrées en AES doivent commencer par le vecteur d'initialisation (IV) utilisé.

## Messages 

Voici une liste exhaustive des différents messages. Les attributs sont listés **dans leur ordre de sérialisation**.

### RsaKeyMessage (ID : 78)
- sessionId : String
### PingMessage (ID : 10)
- pingData : String
### AuthMessage (ID : 4444)
- sessionId : String
- salt : String
- user : String
- pass : String
### GetFileMessage (ID : 666)
- sessionId : String
- path : String
### GetFilesMessage (ID : 45)
- sessionId : String
- path : String
### ErrorMessage (ID : 1)
- error : String
### ConnectMessage (ID : 1921)
- data : String
### SessionKeyMessage (ID : 1337)
- sessionId : String
- aesKey : String
### RsaKeyReply (ID : 98)
- publicKey : String
### ConnectReply (ID : 4875)
- sessionID : String
- flag : String
### PingReply (ID : 11)
- pingData : String
### SessionKeyReply (ID : 1338)
- salt : String
### AuthReply (ID : 6789)
- status : String
- flag : String
### GetFileReply (ID : 7331)
- fileContent : String
### GetFilesReply (ID : 46)
- files : String