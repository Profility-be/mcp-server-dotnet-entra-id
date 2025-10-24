using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using MCP.Models;

namespace MCP.Services;

/// <summary>
/// Manages PKCE state parameters with encryption for security.
/// Uses IMemoryCache for in-memory storage.
/// </summary>
public interface IPkceStateManager
{
    string EncryptAndStoreState(PkceStateData stateData);
    PkceStateData? DecryptAndRetrieveState(string encryptedState);
    void RemoveState(string encryptedState);
}

public class PkceStateManager : IPkceStateManager
{
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _configuration;
    private readonly byte[] _encryptionKey;
    private const int STATE_EXPIRATION_MINUTES = 10;

    public PkceStateManager(IMemoryCache cache, IConfiguration configuration)
    {
        _cache = cache;
        _configuration = configuration;
        
        // Generate a consistent encryption key from configuration or use a random one
        // In production, store this in Azure Key Vault or secure configuration
        var keyString = _configuration["Jwt:EncryptionKey"] ?? GenerateRandomKey();
        _encryptionKey = SHA256.HashData(Encoding.UTF8.GetBytes(keyString));
    }

    public string EncryptAndStoreState(PkceStateData stateData)
    {
        // Serialize the state data
        var json = JsonSerializer.Serialize(stateData);
        var plainBytes = Encoding.UTF8.GetBytes(json);

        // Encrypt using AES
        using var aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        // Combine IV + encrypted data
        var combined = new byte[aes.IV.Length + encryptedBytes.Length];
        Buffer.BlockCopy(aes.IV, 0, combined, 0, aes.IV.Length);
        Buffer.BlockCopy(encryptedBytes, 0, combined, aes.IV.Length, encryptedBytes.Length);

        // Base64 encode for URL safety
        var encryptedState = Convert.ToBase64String(combined)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");

        // Store in cache with expiration
        var cacheKey = $"pkce_state:{encryptedState}";
        _cache.Set(cacheKey, stateData, TimeSpan.FromMinutes(STATE_EXPIRATION_MINUTES));

        return encryptedState;
    }

    public PkceStateData? DecryptAndRetrieveState(string encryptedState)
    {
        try
        {
            // Try to get from cache first (faster and validates expiration)
            var cacheKey = $"pkce_state:{encryptedState}";
            if (_cache.TryGetValue<PkceStateData>(cacheKey, out var cachedData))
            {
                return cachedData;
            }

            // If not in cache, try to decrypt (backup)
            // Restore Base64 padding
            var base64 = encryptedState.Replace('-', '+').Replace('_', '/');
            var padding = (4 - (base64.Length % 4)) % 4;
            base64 = base64.PadRight(base64.Length + padding, '=');

            var combined = Convert.FromBase64String(base64);

            using var aes = Aes.Create();
            aes.Key = _encryptionKey;

            // Extract IV (first 16 bytes)
            var iv = new byte[aes.IV.Length];
            Buffer.BlockCopy(combined, 0, iv, 0, iv.Length);
            aes.IV = iv;

            // Extract encrypted data
            var encryptedBytes = new byte[combined.Length - iv.Length];
            Buffer.BlockCopy(combined, iv.Length, encryptedBytes, 0, encryptedBytes.Length);

            // Decrypt
            using var decryptor = aes.CreateDecryptor();
            var plainBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            var json = Encoding.UTF8.GetString(plainBytes);

            return JsonSerializer.Deserialize<PkceStateData>(json);
        }
        catch
        {
            return null;
        }
    }

    public void RemoveState(string encryptedState)
    {
        var cacheKey = $"pkce_state:{encryptedState}";
        _cache.Remove(cacheKey);
    }

    private static string GenerateRandomKey()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
}
