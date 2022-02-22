using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace Cryptography
{
    /// <summary>
    /// Symmetric encryption using AES and passphrase.
    /// </summary>
    public class AES
    {
        #region Decrypt

        /// <summary>
        /// Decrypt the input string.
        /// </summary>
        /// <param name="input">Input string.</param>
        /// <param name="passphrase">Passphrase to use.</param>
        /// <param name="keySize">Key size to set.</param>
        /// <returns>Decrypted string.</returns>
        public static string Decrypt(
            string input,
            string passphrase,
            int? keySize = null)
        {
            var key = CreateMd5Hash(passphrase);
            var fullCipher = Convert.FromBase64String(input);
            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, fullCipher.Length - iv.Length);

            string result;

            using var aes = Aes.Create();

            if (keySize.HasValue &&
                keySize.Value > 0)
            {
                aes.KeySize = keySize.Value;
            }
            else if (aes.LegalKeySizes?.Length > 0)
            {
                aes.KeySize = aes.LegalKeySizes
                    .Max(n => n.MaxSize);
            }

            using var decryptor = aes.CreateDecryptor(key, iv);
            using var memoryStream = new MemoryStream(cipher);
            using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

            using (var streamReader = new StreamReader(cryptoStream))
            {
                result = streamReader.ReadToEnd();
            }

            return result;
        }

        #endregion

        #region Encrypt

        /// <summary>
        /// Encrypt the input string.
        /// </summary>
        /// <param name="input">Input string.</param>
        /// <param name="passphrase">Passphrase to use.</param>
        /// <param name="keySize">Key size to set.</param>
        /// <returns>Encrypted string.</returns>
        public static string Encrypt(
            string input,
            string passphrase,
            int? keySize = null)
        {
            var key = CreateMd5Hash(passphrase);

            using var aes = Aes.Create();

            if (keySize.HasValue &&
                keySize.Value > 0)
            {
                aes.KeySize = keySize.Value;
            }
            else if (aes.LegalKeySizes?.Length > 0)
            {
                aes.KeySize = aes.LegalKeySizes
                    .Max(n => n.MaxSize);
            }

            using var encryptor = aes.CreateEncryptor(key, aes.IV);
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

            using (var streamWriter = new StreamWriter(cryptoStream))
            {
                streamWriter.Write(input);
            }

            var iv = aes.IV;
            var bytes = memoryStream.ToArray();
            var result = new byte[iv.Length + bytes.Length];

            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(bytes, 0, result, iv.Length, bytes.Length);

            return Convert.ToBase64String(result);
        }

        #endregion

        #region Helper functions

        /// <summary>
        /// Create a MD5 hash of the input string.
        /// </summary>
        /// <param name="input">Input string.</param>
        /// <returns>Created MD5 hash.</returns>
        private static byte[] CreateMd5Hash(string input)
        {
            using var md5 = MD5.Create();

            var inputBytes = Encoding.ASCII.GetBytes(input);
            var hashBytes = md5.ComputeHash(inputBytes);
            var sb = new StringBuilder();

            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("X2"));
            }

            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        #endregion
    }

    /// <summary>
    /// Asymmetric encryption using RSA and public/private key.
    /// </summary>
    public class RSA
    {
        /// <summary>
        /// Decrypt the input string.
        /// </summary>
        /// <param name="input">Input string.</param>
        /// <param name="key">Private/public key to use.</param>
        /// <returns>Decrypted string.</returns>
        public static string Decrypt(string input, string key)
        {
            var stringReader = new StringReader(key);
            var serializer = new XmlSerializer(typeof(RSAParameters));
            var deskey = (RSAParameters)serializer.Deserialize(stringReader);

            var bytes = Decrypt(
                Convert.FromBase64String(input),
                deskey);

            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Decrypt the input bytes.
        /// </summary>
        /// <param name="input">Input bytes.</param>
        /// <param name="key">Private/public key to use.</param>
        /// <returns>Decrypted bytes.</returns>
        public static byte[] Decrypt(byte[] input, RSAParameters key)
        {
            using var rsa = System.Security.Cryptography.RSA.Create(key);

            var bytes = rsa.Decrypt(
                input,
                RSAEncryptionPadding.OaepSHA1);

            return bytes;
        }

        /// <summary>
        /// Encrypt the input string.
        /// </summary>
        /// <param name="input">Input string.</param>
        /// <param name="key">Key to encrypt with.</param>
        /// <returns>Encrypted string.</returns>
        public static string Encrypt(string input, string key)
        {
            var stringReader = new StringReader(key);
            var serializer = new XmlSerializer(typeof(RSAParameters));
            var deskey = (RSAParameters)serializer.Deserialize(stringReader);

            var bytes = Encrypt(
                Encoding.UTF8.GetBytes(input),
                deskey);

            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Encrypt the input bytes.
        /// </summary>
        /// <param name="input">Input bytes.</param>
        /// <param name="key">Key to encrypt with.</param>
        /// <returns>Encrypted bytes.</returns>
        public static byte[] Encrypt(byte[] input, RSAParameters key)
        {
            using var rsa = System.Security.Cryptography.RSA.Create(key);

            var bytes = rsa.Encrypt(
                input,
                RSAEncryptionPadding.OaepSHA1);

            return bytes;
        }

        /// <summary>
        /// Generate a set of private and public keys for RSA encryption.
        /// </summary>
        /// <param name="privateKey">Generated private key.</param>
        /// <param name="publicKey">Generated public key.</param>
        /// <param name="keySize">Desired key size.</param>
        /// <returns>Success.</returns>
        public static bool GenerateKeys(
            out string privateKey,
            out string publicKey,
            int keySize = 2048)
        {
            var csp = new RSACryptoServiceProvider(keySize);

            // Public key.
            var pubKey = csp.ExportParameters(false);

            var stringWriter = new StringWriter();
            var serializer = new XmlSerializer(typeof(RSAParameters));

            serializer.Serialize(stringWriter, pubKey);
            publicKey = stringWriter.ToString();

            // Private key.
            var privKey = csp.ExportParameters(true);

            stringWriter = new StringWriter();
            serializer = new XmlSerializer(typeof(RSAParameters));

            serializer.Serialize(stringWriter, privKey);
            privateKey = stringWriter.ToString();

            // Done.
            return true;
        }
    }
}