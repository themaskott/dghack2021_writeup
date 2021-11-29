# Crypto be crush

![Consignes](images/consignes.png)

Un challenge de crypto qui nous demande de décrypter un échange intercepté contenant le précieux flag.

On nous fournit quelques fichiers :
- Submission.md : décrit le processus de soumission de flag dont on a capturé un échange
- encrypt_challenge.py : le code qui tourne sur le serveur et qui nous servira à chiffrer notre envoie
- ex_flag.json : un exemple du format de réponse à fournir


## Analyse

Nous avons donc à notre disposition :
- le chiffré
- le script qui a servi à produire ce chiffré
- le format du clair correspondant


Ce clair est de la forme :

```
{"sig":"80a7ccd5aa2f3b0f917267640c6ff37c50e7f3673a30d20c0e133fe8c20d5cd1","flag":"DG'hAck-{{b51613f7}}","user":"JohnDoe","cid":4}
```

Par ailleurs, quelques renseignements donnés en consignes vont être utiles :
- la personne ayant soumit son flag est "Alice"
- il s'agit du 10e encrypt_challenge

Nous pouvons alors supposer que le clair est de la forme

```
{"sig":"80a7ccd5aa2f3b0f917267640c6ff37c50e7f3673a30d20c0e133fe8c20d5cd1","flag":"DG'hAck-{{b51613f7}}","user":"Alice","cid":10}
```

Ce qui de façon intéressante fait 128 octets de long, soit 8 blocs de 16 octets.

Le chiffré quant à lui peux être découpé de la sorte (10 blocs de 16 octets):

```
IV
61499b3f31cee611a72eaf3cbfcf7d1c

ebb228a44db94e7b0504c145fcf00e57
d2e0b9e24c7259bbeebccd03c100a645
f418f2f58cc073cc71f214eb64a3b20d
dfb406f6ebbd6781119efe13116af3ab
fe52609961727213ea69b8f8f1e4298e
d3a42bc9ae4b8f1785184153ee3e113a
8c9d55ddec48c85c53d5aa4a4089e47c
3026a0bdb4d5d2659e57c31a76cca407

padding
ea0a92430d8540b8ef677405e8c4b193
```

Si notre intuition est bonne on aura :
- l'IV en en-tête
- 8 blocs pour le message chiffré
- 1 bloc de padding

Ce dernier devrait être le chiffré de "\x0a\x0a\x0a\x0a...\x0a" puisque la taille du clair tombe pile sur un multiple de "AES.block_size"

## Vérification

Dans un premier temps on soumet au serveur de chiffrement la chaine de padding "\x0a ... \x0a" avec pour IV le bloc précédent ( ici : 3026a0bdb4d5d2659e57c31a76cca407 ).

(Pour plus d'infos : https://fr.wikipedia.org/wiki/Mode_d%27op%C3%A9ration_(cryptographie) )

Et le serveur nous répond : ea0a92430d8540b8ef677405e8c4b193

Notre démarche n'est peut être pas absurde.

En regardant bien, on connait les 16 derniers octets du clair : **Alice","cid":10}**

De la même façon on vérifie cela sur le serveur de chiffrement en soumettant cette chaîne au serveur avec pour IV le bloc n-2 (8c9d55ddec48c85c53d5aa4a4089e47c)
Le serveur nous répond : **3026a0bdb4d5d2659e57c31a76cca407**

C'est à dire le dernier bloc de notre chiffré.

## Retrouver le flag

Si on continue à remonter dans la structure du clair on a les 16 octets : **xxxx}}","user":"**

On connaît 12 des 16 octets de ce bloc.

Et pour le précédent : **:"DG'hAck-{{xxxx**


L'idée est donc de brutfrocer deux fois sur les caractères qui nous manquent. 4 dans chaque portion du flag.


Le code qui m'a servi (pas très propre, il est tel quel )

En gros le chiffré est stocké en liste de bloc de 16 octets.
On brutforce sur le clair partiel en comparant avec le bloc correspondant dans le chiffré.
Il faut répéter l'opération pour la 2e partie du flag.

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto import Random
import secrets
import socket
from random import randint

CIPHER = bytes.fromhex(open('cipher.txt', 'r').read())

HOST = "cryptobecrushed.chall.malicecyber.com"
PORT = 4242

def pkcs7_padding(m):
    # There is padding and there is PKCS#7 padding
    l = len(m)
    pad_len = 16 - (l % 16)
    pad_len_hex = pad_len.to_bytes(1, byteorder="little")
    padding = bytes([pad_len_hex[0] for i in range(0, pad_len)])

    return m+padding


def decrypt(iv, m):

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return cipher.decrypt(m)

def xor(key, cipher):
	return bytes(a ^ b for a, b in zip(key, cipher) )

# stdin/stdout version
if __name__ == "__main__":
    print("Input challenge :", CIPHER.hex() )
    iv = CIPHER[0 : AES.block_size ]
    ciphered = CIPHER[AES.block_size:]
    print("Iv : ", iv.hex() )
    print("Ciphered :", ciphered.hex() )
    print("Len : ", len(ciphered))


    ciphered_blocks = []
    nb_block = int( len(ciphered) / ( AES.block_size ) )
    print("Nb de block : ", nb_block )
    for i in range(nb_block):
        ciphered_blocks.append( ciphered[i * AES.block_size : (i+1) * AES.block_size ])

    ch = list(x.hex() for x in ciphered_blocks )
    for c in ch: print(c)

    #print("Chiphered : ", ciphered_blocks )

    #last = pkcs7_padding(b'')
    last = b'Alice","cid":10}'

    n = 7

    print('Last : ', last)
    print('size : ', len(last) )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    rep = s.recv(1024)
    iv_tmp = str(rep).split('\\n')[1]
    print('Iv server : ' + iv_tmp)

    #message = xor(ciphered_blocks[0], iv)
    #message = xor(message, bytes.fromhex(iv_tmp))

    message = xor( last, ciphered_blocks[ n - 1] )
    message = xor(message, bytes.fromhex(iv_tmp))

    s.send( bytes( message.hex(), 'utf-8') + b'\n' )
    rep = s.recv(1024)

    serv_cipher = rep.decode('utf-8')
    serv_cipher = serv_cipher.split('\n')[0]
    serv_cipher = serv_cipher.split(' ')[2]
    serv_cipher = serv_cipher[32:64]

    print( 'Block : ', ciphered_blocks[ n ].hex())
    print( 'Serv cipher : ' + serv_cipher )
    print( 'Size : ', len(serv_cipher ))

    print( serv_cipher == ciphered_blocks[ n ].hex())

    print('------------------------------------------')

    #last = b'}}","user":"'

    last = b':"DG\'hAck-{{'

    n = 5

    hex_alph = '0123456789abcdef'
    hex_alph = 'fedcba9876543210'

    for b1 in hex_alph:
        for b2 in hex_alph:
            for b3 in hex_alph:
                for b4 in hex_alph:
                    iv_tmp = rep.decode('utf-8').split('\n')[3]

                    last = b':"DG'+ b"'" +b'hAck-{{' + b1.encode('utf-8') + b2.encode('utf-8') + b3.encode('utf-8') + b4.encode('utf-8')
                    print(last)
                    print(len(last))

                    print('Iv server : ' + iv_tmp)

                    message = xor( last, ciphered_blocks[ n - 1] )
                    message = xor(message, bytes.fromhex(iv_tmp))

                    s.send( bytes( message.hex(), 'utf-8') + b'\n' )
                    rep = s.recv(1024)

                    serv_cipher = rep.decode('utf-8')
                    serv_cipher = serv_cipher.split('\n')[0]
                    serv_cipher = serv_cipher.split(' ')[2]
                    serv_cipher = serv_cipher[32:64]

                    print( 'Block : ', ciphered_blocks[ n ].hex())
                    print( 'Serv cipher : ' + serv_cipher )
                    print( 'Size : ', len(serv_cipher ))

                    if ( serv_cipher == ciphered_blocks[ n ].hex()):
                        b1ok = b1
                        b2ok = b2
                        b3ok = b3
                        b4ok = b4
                        print(b1, b2, b3, b4)
                        exit(0)
                        break
                        break
                        break
                        break

    print(b1ok, b2ok, b3ok, b4ok)

```

Falg : **DG'hAck-{{e20eb967}}**
