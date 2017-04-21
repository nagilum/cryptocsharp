# Cryptography

C# lib to encrypt and decrypt data with symmetric/asymmetric algorithms

## Asymmetric

The asymmetric portion of the Cryptography library lets you create and use public and private keys.

### Create Keys

```
// This will create both a public and private key with a 4096 key-size.
// You can specify your own key-size as the third parameter to the function.
if (Cryptography.Asymmetric.RSA.CreateKeys(
    out string publicKey,
    out string privateKey)) {
  // Do something fancy with the keys, but
  // keep the private one secret and safe.
}
```

### Encrypt

```
var encryptedBytes = Cryptography.Asymmetric.RSA.Encrypt(plainBytes, publicKey);
```

### Decrypt

```
var decryptedBytes = Cryptography.Asymmetric.RSA.Decrypt(encryptedBytes, privateKey);
```

## Symmetric

The symmetric portion of the Cryptography library lets you encrypt and decrypt large-scale data using a password.

### Encrypt

```
// This will encrypt data using Rijndael.
var encryptedBytes = Cryptography.Symmetric.Encrypt(plainBytes, password);

// You can specify your own symmetric algorithm, like so..
var encryptedBytes = Cryptography.Symmetric.Encrypt<RijndaelManaged>(plainBytes, password);
```

### Decrypt

```
// This will decrypt data using Rijndael.
var decryptedBytes = Cryptography.Symmetric.Decrypt(encryptedBytes, password);

// As with encrypt, you can specify your own symmetric algorithm, like so..
var decryptedBytes = Cryptography.Symmetric.Decrypt<RijndaelManaged>(encryptedBytes, password);
```

### Iterations, KeySize, and Salt

The iterations, key-size, and salt variables are pre-defined in this library, but you can easily change them.

```
Cryptography.Symmetric.Iterations = 4; // defaults to 2

Cryptography.Symmetric.KeySize = 196; // defaults to 256.

Cryptography.Symmetric.Salt = { ... }; // see source-code for default ;)
```