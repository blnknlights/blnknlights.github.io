# Hashes

## Useful documentation & resources
[https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)  

## Hashid
```bash
hashid '${hash}'      # to get an idea of what the hash is
hashid '${hash}' -m   # to get the corresponding hashcat module
```

## Storage format examples
```
hash:salt
$id$salt$hash
```

## Algorythms
```
MD5        -> 32chr -> file integrity (vulnerable to collisions)
SHA256     ->       -> file integrity
SHA1       ->       ->
HMAC       ->       -> transmission integrity (Keyed)
PBKDF2     ->       -> password storage
NTLM       -> 32chr -> windows passwords
```

## Lexicon
```
KEYING     -> an additionnal secret is used at creation time
COLLISION  -> where two sets of plaintext can produce the same hash
SALTING    -> a random piece of data is added to the plaintext before hashing
ID         -> used to identify the type of algo
SYMMETRIC   -> same key (or secret) to encrypt and decrypt
ASSYMMETRIC -> public and private keys
```

## Symmetric encryption
algorythms
```
CAESAR CIPHER
BACON'S CIPHER
SUBSTITUTION CIPHER
XOR
AES
DES
3DES
Blowfish
```

attacks
```
frequency analysis
padding oracle attack
```

## ASSYMMETRIC ENCRYPTION
algorythms
```
RSA
ECDSA
Diffie-Hellman
```


## ColabCat

Tried this colabcat thing, which runs hashcat on google Colab, which is some kind of jupiter notebook service on spare GCP GPU instances apparently, and for free, but my account has been blocked apparently. Maybe they cracked down on this now, that wouldn't be surprising.
[https://github.com/someshkar/colabcat](https://github.com/someshkar/colabcat)  

```
Connection failed
This account has been blocked from accessing Colab runtimes due to suspected abusive activity. This does not impact access to other Google products. If you believe this has been done in error, review the usage limitations and file an appeal.
```
Yea. No kidding
