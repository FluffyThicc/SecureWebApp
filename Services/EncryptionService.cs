using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace SecureWebApp.Services;

public class EncryptionService
{
    private readonly string _encryptionKey;
    private readonly byte[] _keyBytes;
    private readonly byte[] _ivBytes;

    public EncryptionService(IConfiguration configuration)
    {
        // Try environment variable first, then fall back to configuration
        _encryptionKey = Environment.GetEnvironmentVariable("ENCRYPTION_KEY") 
            ?? configuration["Encryption:Key"] 
            ?? "DefaultEncryptionKey123456789012345678901234567890";
        
        // Derive key and IV from the encryption key
        using (var sha256 = SHA256.Create())
        {
            _keyBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(_encryptionKey));
        }
        
        using (var md5 = MD5.Create())
        {
            _ivBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(_encryptionKey));
        }
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        using (Aes aes = Aes.Create())
        {
            aes.Key = _keyBytes;
            aes.IV = _ivBytes;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                return Convert.ToBase64String(encryptedBytes);
            }
        }
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        try
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = _keyBytes;
                aes.IV = _ivBytes;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    byte[] cipherBytes = Convert.FromBase64String(cipherText);
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
        catch
        {
            return string.Empty;
        }
    }
}

