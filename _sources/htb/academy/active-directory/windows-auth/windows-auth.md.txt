# Windows Authentication

## SID - (Security Identifier)
[https://morgantechspace.com/2013/10/difference-between-rid-and-sid-in.html](https://morgantechspace.com/2013/10/difference-between-rid-and-sid-in.html)

```
S-1-5-21-4064627337-2434140041-2375368561-1036

S: Stands for SID
1: v1 of the SID spec
5: The identifier authority value, typically 5, aka SECURITY_NT_AUTHORITY
21-4064627337-2434140041-2375368561: id of the computer or domain that created the SID
1036: RID (Relative ID) a principal (user or group) relative to the local or domain security 
```


## Windows Authentication Mechanisms

### LM Hash
```
- 14 chr password (or padded with null)
- split into two seven-character chunks
- Two DES keys are created from each chunk
- These chunks are then encrypted using the string KGS!@#$%
- creating two 8-byte ciphertext values.
- These two values are then concatenated together
- and that's an LM hash
```

### NT Hash
```
- password in little-endian UTF-16 format
- MD4 hashed
- MD4(UTF-16-LE(password))
```

### NTLM protocol
```
- NTLM is a challenge-response authentication protocol
- NTLM can user either the LM hash or The NT hash
- NTLM hashes are stored locally in
- The SAM database on a machine or
- The NTDS.DIT datable on a DC

- The authentication flow looks like this:
-- client ->  NEGOTIATE_MESSAGE   -> server
-- client <-  CHALLENGE_MESSAGE   <- server
-- client -> AUTHENTICATE_MESSAGE -> server
```
