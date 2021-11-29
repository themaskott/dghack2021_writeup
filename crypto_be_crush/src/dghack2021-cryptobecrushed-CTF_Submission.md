# CTF Submission instructions

Welcome to the CTF, player!

This year, for security purposes, we decided to use specific procedure for you to use when submitting a flag.
Indeed, it must be submitted in a CBC-encrypted-JSON with a per-user key. We sent you the key at registration.
If you are not comfy with cryptography, no worries, you will find the code in the FAQ (`encrypt_challenge.py`, which uses the `PyCryptodome` library -- *don't roll your own crypto*).
You will just have to put your provided key in a `key.txt` file.

To be properly processed, the JSON file must have the following format :
- a `"sig"` value, with a random 32 bytes values encoded as a hex string which is provided to you for each challenge;
- a `"flag"` value containing the submitted flag;
- a `"user"` value, the user's login;
- and a `"cid"` value, which is the challenge id.

An example JSON is provided by the `ex_flag.json` file.

Happy hacking!
