using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

public class Cryptography
{
    public class Asymmetric
    {
        public class RSA
        {
            /// <summary>
            /// Create a public and private key.
            ///
            /// The RSACryptoServiceProvider supports key sizes from 384
            /// bits to 16384 bits in increments of 8 bits if you have the
            /// Microsoft Enhanced Cryptographic Provider installed. It
            /// supports key sizes from 384 bits to 512 bits in increments
            /// of 8 bits if you have the Microsoft Base Cryptographic
            /// Provider installed.
            /// </summary>
            /// <param name="publicKey">The created public key.</param>
            /// <param name="privateKey">The created private key.</param>
            /// <param name="keySize">Size of keys.</param>
            public static void CreateKeys(out string publicKey, out string privateKey, int keySize = 4096)
            {
                publicKey = null;
                privateKey = null;

                var csp = new CspParameters
                {
                    ProviderType = 1,
                    Flags = CspProviderFlags.UseArchivableKey,
                    KeyNumber = (int) KeyNumber.Exchange
                };

                using var rsa = new RSACryptoServiceProvider(keySize, csp);

                publicKey = rsa.ToXmlString(false);
                privateKey = rsa.ToXmlString(true);

                rsa.PersistKeyInCsp = false;
            }

            /// <summary>
            /// Encrypt data using a public key.
            /// </summary>
            /// <param name="bytes">Bytes to encrypt.</param>
            /// <param name="publicKey">Public key to use.</param>
            /// <returns>Encrypted data.</returns>
            public static byte[] Encrypt(byte[] bytes, string publicKey)
            {
                var csp = new CspParameters
                {
                    ProviderType = 1
                };

                using var rsa = new RSACryptoServiceProvider(csp);

                rsa.FromXmlString(publicKey);
                var data = rsa.Encrypt(bytes, false);

                rsa.PersistKeyInCsp = false;

                return data;
            }

            /// <summary>
            /// Encrypt data using a public key.
            /// </summary>
            /// <param name="input">Data to encrypt.</param>
            /// <param name="publicKey">Public key to use.</param>
            /// <returns>Encrypted data.</returns>
            public static string Encrypt(string input, string publicKey)
            {
                if (input == null)
                {
                    throw new Exception("Input cannot be null");
                }

                return Convert.ToBase64String(
                    Encrypt(
                        Encoding.UTF8.GetBytes(input),
                        publicKey));
            }

            /// <summary>
            /// Decrypt data using a private key.
            /// </summary>
            /// <param name="bytes">Bytes to decrypt.</param>
            /// <param name="privateKey">Private key to use.</param>
            /// <returns>Decrypted data.</returns>
            public static byte[] Decrypt(byte[] bytes, string privateKey)
            {
                var csp = new CspParameters
                {
                    ProviderType = 1
                };

                using var rsa = new RSACryptoServiceProvider(csp);

                rsa.FromXmlString(privateKey);
                var data = rsa.Decrypt(bytes, false);

                rsa.PersistKeyInCsp = false;

                return data;
            }

            /// <summary>
            /// Decrypt data using a private key.
            /// </summary>
            /// <param name="input">Base64 data to decrypt.</param>
            /// <param name="privateKey">Private key to use.</param>
            /// <returns>Decrypted data.</returns>
            public static string Decrypt(string input, string privateKey)
            {
                if (input == null)
                {
                    throw new Exception("Input cannot be null");
                }

                return Encoding.UTF8.GetString(
                    Decrypt(
                        Convert.FromBase64String(input),
                        privateKey));
            }
        }
    }

    public class Symmetric
    {
        /// <summary>
        /// Number of iterations for block chain.
        /// </summary>
        public static int Iterations = 2;

        /// <summary>
        /// Key size for encrypting/decrypting.
        /// The valid key sizes for Rijndael are 128, 192 and 256 bits.
        /// </summary>
        public static int KeySize = 256;

        /// <summary>
        /// Salt for password hashing.
        /// </summary>
        public static byte[] Salt = {
            0x26, 0xdc, 0xff, 0x00,
            0xad, 0xed, 0x7a, 0xee,
            0xc5, 0xfe, 0x07, 0xaf,
            0x4d, 0x08, 0x22, 0x3c
        };

        /// <summary>
        /// Encrypt data using a passphrase and a given algorithm.
        /// </summary>
        /// <typeparam name="T">Algorithm to use.</typeparam>
        /// <param name="bytes">Bytes to encrypt.</param>
        /// <param name="passphrase">Passphrase to use.</param>
        /// <returns>Encrypted data.</returns>
        public static byte[] Encrypt<T>(byte[] bytes, string passphrase) where T : SymmetricAlgorithm, new()
        {
            using var cipher = new T();

            var pwdBytes = new Rfc2898DeriveBytes(
                Encoding.UTF7.GetBytes(passphrase),
                Salt,
                Iterations);

            var keyBytes = pwdBytes.GetBytes(KeySize / 8);

            cipher.Mode = CipherMode.CBC;

            using var encryptor = cipher.CreateEncryptor(keyBytes, pwdBytes.GetBytes(16));
            using var stream = new MemoryStream();
            using var writer = new CryptoStream(stream, encryptor, CryptoStreamMode.Write);

            writer.Write(bytes, 0, bytes.Length);
            writer.FlushFinalBlock();

            var data = stream.ToArray();

            cipher.Clear();

            return data;
        }

        /// <summary>
        /// Encrypt data using a passphrase and the Rijndael/AES algorithm.
        /// </summary>
        /// <param name="bytes">Bytes to encrypt.</param>
        /// <param name="passphrase">Passphrase to use.</param>
        /// <returns>Encrypted data.</returns>
        public static byte[] Encrypt(byte[] bytes, string passphrase)
        {
            return Encrypt<RijndaelManaged>(
                bytes,
                passphrase);
        }

        /// <summary>
        /// Encrypt data using a passphrase and the Rijndael/AES algorithm.
        /// </summary>
        /// <param name="input">Data to encrypt.</param>
        /// <param name="passphrase">Passphrase to use.</param>
        /// <returns>Encrypted data.</returns>
        public static string Encrypt(string input, string passphrase)
        {
            return Convert.ToBase64String(
                Encrypt(
                    Encoding.UTF8.GetBytes(input),
                    passphrase));
        }

        /// <summary>
        /// Decrypt data using a passphrase and a given algorithm.
        /// </summary>
        /// <typeparam name="T">Algorithm to use.</typeparam>
        /// <param name="bytes">Bytes to decrypt.</param>
        /// <param name="passphrase">Passphrase to use.</param>
        /// <returns>Decrypted data.</returns>
        public static byte[] Decrypt<T>(byte[] bytes, string passphrase) where T : SymmetricAlgorithm, new()
        {
            using var cipher = new T();

            var pwdBytes = new Rfc2898DeriveBytes(
                Encoding.UTF7.GetBytes(passphrase),
                Salt,
                Iterations);

            var keyBytes = pwdBytes.GetBytes(KeySize / 8);

            cipher.Mode = CipherMode.CBC;

            using var decryptor = cipher.CreateDecryptor(keyBytes, pwdBytes.GetBytes(16));
            using var stream = new MemoryStream(bytes);
            using var reader = new CryptoStream(stream, decryptor, CryptoStreamMode.Read);

            var data = new byte[stream.Length];

            reader.Read(data, 0, data.Length);

            cipher.Clear();

            return data
                .Where(b => b != 0)
                .ToArray();
        }

        /// <summary>
        /// Decrypt data using a passphrase and the Rijndael/AES algorithm.
        /// </summary>
        /// <param name="bytes">Bytes to decrypt.</param>
        /// <param name="passphrase">Passphrase to use.</param>
        /// <returns>Decrypted data.</returns>
        public static byte[] Decrypt(byte[] bytes, string passphrase)
        {
            return Decrypt<RijndaelManaged>(
                bytes,
                passphrase);
        }

        /// <summary>
        /// Decrypt data using a passphrase and the Rijndael/AES algorithm.
        /// </summary>
        /// <param name="input">Data to decrypt.</param>
        /// <param name="passphrase">Passphrase to use.</param>
        /// <returns>Decrypted data.</returns>
        public static string Decrypt(string input, string passphrase)
        {
            return Encoding.UTF8.GetString(
                Decrypt(
                    Convert.FromBase64String(input),
                    passphrase));
        }
    }
}