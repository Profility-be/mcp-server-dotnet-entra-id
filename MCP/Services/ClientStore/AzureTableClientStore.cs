using Azure;
using Azure.Data.Tables;
using MCP.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Profility.MCP.Services.ClientStore;

/// <summary>
/// Azure Table Storage implementation of IClientStore.
/// Stores client registrations in Azure Table Storage.
/// Uses deterministic client IDs based on registration parameters.
/// Same parameters = same client ID (persistent across restarts with same params).
/// </summary>
public class AzureTableClientStore : IClientStore
{
    private readonly TableClient _tableClient;

    public AzureTableClientStore(string connectionString, string tableName)
    {
        _tableClient = new TableClient(connectionString, tableName);
        
        // Ensure table exists
        _tableClient.CreateIfNotExists();
    }

    public async Task<string> RegisterClient(string clientName, List<string> redirectUris, string? requestedScopes)
    {
        // Generate deterministic client ID based on registration parameters
        var proxyClientId = GenerateDeterministicClientId(clientName, redirectUris, requestedScopes);

        // Check if the client already exists
        var existingMapping = await GetClientMapping(proxyClientId);
        if (existingMapping != null)
        {
            return proxyClientId; // Already registered with same parameters
        }

        var entity = new ClientMappingEntity
        {
            PartitionKey = "ClientRegistration", // Single partition for simplicity
            RowKey = proxyClientId,
            ClientName = clientName,
            RedirectUrisJson = JsonSerializer.Serialize(redirectUris),
            RequestedScopes = requestedScopes,
            CreatedAt = DateTime.UtcNow
        };

        await _tableClient.UpsertEntityAsync(entity);
        
        return proxyClientId;
    }

    private static string GenerateDeterministicClientId(string clientName, List<string> redirectUris, string? scopes)
    {
        // Create stable hash input (sorted for consistency)
        var sortedRedirects = string.Join("|", redirectUris.OrderBy(x => x));
        var input = $"{clientName}|{sortedRedirects}|{scopes ?? ""}";
        
        // Generate SHA-256 hash
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        
        // Convert to base64url (RFC 7515) and take first 32 chars for readability
        var base64 = Convert.ToBase64String(hashBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
        
        return base64[..32]; // 32 characters = 192 bits of entropy
    }

    public async Task<ClientMapping?> GetClientMapping(string proxyClientId)
    {
        try
        {
            var response = await _tableClient.GetEntityAsync<ClientMappingEntity>("ClientRegistration", proxyClientId);
            var entity = response.Value;

            var mapping = new ClientMapping
            {
                ProxyClientId = entity.RowKey,
                ClientName = entity.ClientName,
                RedirectUris = JsonSerializer.Deserialize<List<string>>(entity.RedirectUrisJson) ?? new List<string>(),
                RequestedScopes = entity.RequestedScopes,
                CreatedAt = entity.CreatedAt
            };

            return mapping;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            // Client not found
            return null;
        }
    }
}

/// <summary>
/// Azure Table entity for storing ClientMapping.
/// PartitionKey = "ClientRegistration" (single partition)
/// RowKey = ProxyClientId (the generated client ID)
/// </summary>
public class ClientMappingEntity : ITableEntity
{
    public string PartitionKey { get; set; } = default!;
    public string RowKey { get; set; } = default!;
    public DateTimeOffset? Timestamp { get; set; }
    public ETag ETag { get; set; }

    // ClientMapping properties
    public string ClientName { get; set; } = default!;
    public string RedirectUrisJson { get; set; } = default!;
    public string? RequestedScopes { get; set; }
    public DateTime CreatedAt { get; set; }
}
