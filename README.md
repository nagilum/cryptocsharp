# Cryptography
A tiny C# library for encrypting and decrypting data using both symmetric (AES) and asymmetric (RSA) algorithms.

# Symmetric (AES)
Symmetric encryption is best suited for small amounts of data.

```csharp
// Set the passphrase.
const string passphrase = "This is a passphrase";

// Encrypt.
var encrypted = Cryptography.AES.Encrypt(
	"This is some text to encrypt",
	passphrase);

// Decrypt.
var decrypted = Cryptography.AES.Decrypt(
	encrypted,
	passphrase);
```

# Asymmetric (RSA)
Asymmetric encryption is best suited for large amounts of data. With public/private key encryption you can also switch the keys if you wanted, encrypting with the private key and decrypting with the public key.

```csharp
// Generate keys.
Cryptography.RSA.GenerateKeys(
	out var privateKey,
	out var publicKey,
	keySize: 2048); // The keySize is optional and defaults to 2048.

var encrypted = Cryptography.RSA.Encrypt(
	"... this is a large dataset ...",
	publicKey);

var decrypted = Cryptography.RSA.Decrypt(
	encrypted,
	privateKey);
```