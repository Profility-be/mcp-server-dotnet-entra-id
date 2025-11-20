using Azure;
using Azure.Data.Tables;
using MCP.Models;
using System.Text.Json;

namespace Profility.MCP.Services.ClientStore;

/// <summary>
/// Azure Table Storage implementation of IClientStore.
/// Stores client registrations in Azure Table Storage.
/// Uses Guid.NewGuid() for client IDs (non-deterministic).
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
        // Generate random client ID using Guid
        var proxyClientId = Guid.NewGuid().ToString("N"); // 32 hex characters without dashes

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
