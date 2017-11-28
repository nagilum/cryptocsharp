using System.IO;
using System.Security.Cryptography;
using System.Text;

public class Cryptography {
    public class Asymmetric {
        public class RSA {
            /// <summary>
            /// Create public and private keys.
            /// </summary>
            /// <param name="publicKey">The created public key.</param>
            /// <param name="privateKey">The created private key.</param>
            /// <param name="keySize">Size of keys.</param>
            /// <returns>Success</returns>
            public static bool CreateKeys(out string publicKey, out string privateKey, int keySize = 4096) {
                var csp = new CspParameters {
                    ProviderType = 1,
                    Flags = CspProviderFlags.UseArchivableKey,
                    KeyNumber = (int) KeyNumber.Exchange
                };

                using (var rsa = new RSACryptoServiceProvider(keySize, csp)) {
                    try {
                        publicKey = rsa.ToXmlString(false);
                        privateKey = rsa.ToXmlString(true);

                        return true;
                    }
                    finally {
                        rsa.PersistKeyInCsp = false;
                    }
                }
            }

            /// <summary>
            /// Encrypt data using a public key.
            /// </summary>
            /// <param name="bytes">Bytes to encrypt.</param>
            /// <param name="publicKey">Public key.</param>
            /// <returns>Encrypted bytes.</returns>
            public byte[] Encrypt(byte[] bytes, string publicKey) {
                var csp = new CspParameters {
                    ProviderType = 1
                };

                byte[] encrypted;

                using (var rsa = new RSACryptoServiceProvider(csp)) {
                    try {
                        rsa.FromXmlString(publicKey);
                        encrypted = rsa.Encrypt(bytes, false);
                    }
                    finally {
                        rsa.PersistKeyInCsp = false;
                    }
                }

                return encrypted;
            }

            /// <summary>
            /// Decrypt data using a private key.
            /// </summary>
            /// <param name="encrypted">Bytes to decrypt.</param>
            /// <param name="privateKey">Private key.</param>
            /// <returns>Decrypted bytes.</returns>
            public byte[] Decrypt(byte[] encrypted, string privateKey) {
                var csp = new CspParameters {
                    ProviderType = 1
                };

                byte[] bytes;

                using (var rsa = new RSACryptoServiceProvider(csp)) {
                    try {
                        rsa.FromXmlString(privateKey);
                        bytes = rsa.Decrypt(encrypted, false);
                    }
                    finally {
                        rsa.PersistKeyInCsp = false;
                    }
                }

                return bytes;
            }
        }
    }

    public class Symmetric {
        /// <summary>
        /// Number of iterations for block chain.
        /// </summary>
        public static int Iterations = 2;

        /// <summary>
        /// Key size for encrypting/decrypting.
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
        /// Encrypt data using a password and Rijndael.
        /// </summary>
        /// <param name="bytes">Bytes to encrypt.</param>
        /// <param name="password">Password to encrypt with.</param>
        /// <returns>Encrypted bytes.</returns>
        public static byte[] Encrypt(byte[] bytes, string password) {
            return Encrypt<RijndaelManaged>(bytes, password);
        }

        /// <summary>
        /// Encrypt data using a password and a given algorithm.
        /// </summary>
        /// <typeparam name="T">Symmetric algorithm to use.</typeparam>
        /// <param name="bytes">Bytes to encrypt.</param>
        /// <param name="password">Password to encrypt with.</param>
        /// <returns>Encrypted bytes.</returns>
        public static byte[] Encrypt<T>(byte[] bytes, string password) where T : SymmetricAlgorithm, new() {
            byte[] encrypted;

            using (var cipher = new T()) {
                var passwordBytes = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), Salt, Iterations);
                var keyBytes = passwordBytes.GetBytes(KeySize / 8);

                cipher.Mode = CipherMode.CBC;

                using (var encryptor = cipher.CreateEncryptor(keyBytes, passwordBytes.GetBytes(16))) {
                    using (var stream = new MemoryStream()) {
                        using (var writer = new CryptoStream(stream, encryptor, CryptoStreamMode.Write)) {
                            writer.Write(bytes, 0, bytes.Length);
                            writer.FlushFinalBlock();

                            encrypted = stream.ToArray();
                        }
                    }
                }

                cipher.Clear();
            }

            return encrypted;
        }

        /// <summary>
        /// Decrypt data using a password and Rijndael.
        /// </summary>
        /// <param name="encrypted">Bytes to decrypt.</param>
        /// <param name="password">Password to decrypt with.</param>
        /// <returns>Decrypted bytes.</returns>
        public static byte[] Decrypt(byte[] encrypted, string password) {
            return Decrypt<RijndaelManaged>(encrypted, password);
        }

        /// <summary>
        /// Decrypt data using a password and a given algorithm.
        /// </summary>
        /// <typeparam name="T">Symmetric algorithm to use.</typeparam>
        /// <param name="encrypted">Bytes to decrypt.</param>
        /// <param name="password">Password to decrypt with.</param>
        /// <returns>Decrypted bytes.</returns>
        public static byte[] Decrypt<T>(byte[] encrypted, string password) where T : SymmetricAlgorithm, new() {
            byte[] decrypted;

            using (var cipher = new T()) {
                var passwordBytes = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), Salt, Iterations);
                var keyBytes = passwordBytes.GetBytes(KeySize / 8);

                cipher.Mode = CipherMode.CBC;

                using (var decrypter = cipher.CreateDecryptor(keyBytes, passwordBytes.GetBytes(16))) {
                    using (var stream = new MemoryStream(encrypted)) {
                        using (var reader = new CryptoStream(stream, decrypter, CryptoStreamMode.Read)) {
                            decrypted = new byte[stream.Length];
                            reader.Read(decrypted, 0, decrypted.Length);
                        }
                    }
                }

                cipher.Clear();
            }

            return decrypted
                .Where(b => b != 0)
                .ToArray();
        }
    }
}
