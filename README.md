# Cryptography

C# library for encrypting and decrypting data using both asymmetric (pub/priv) and symmetric algorithms.

The asymmetric algorithm in use is RSA.

The default symmetric algorithm is Rijndael/AES.

## Asymmetric

```csharp
// The default key size for the created keys is 4096, but can be specified as the last parameter.
Cryptography.Asymmetric.RSA.CreateKeys(out var publicKey, out var privateKey);

// Encrypt some data with the public key. Can be passed as byte[] too.
var encrypted = Cryptography.Asymmetric.RSA.Encrypt("This is a test", publicKey);

// Decrypt the encrypted data with the private key.
var decrypted = Cryptography.Asymmetric.RSA.Decrypt(encrypted, privateKey);
```

## Symmetric

```csharp
// Rijndael is assumed if you don't specify a symmetric algorithm.
var encrypted = Cryptography.Symmetric.Encrypt("This is a test", "This is a passphrase");

// Decrypt.
var decrypted = Cryptography.Symmetric.Decrypt(encrypted, "This is a passphrase");
```

`Iterations`, `KeySize`, and `Salt` can be changed directly on the Symmetric class.