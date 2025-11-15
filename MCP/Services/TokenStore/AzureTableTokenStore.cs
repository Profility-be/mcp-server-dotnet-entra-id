using Azure;
using Azure.Data.Tables;
using MCP.Controllers;
using MCP.Models;
using System.Text.Json;

namespace Profility.MCP.Services.TokenStore;

/// <summary>
/// Azure Table Storage implementation of ITokenStore.
/// Stores token data in Azure Table Storage with automatic expiration.
/// </summary>
public class AzureTableTokenStore : ITokenStore
{
    private readonly TableClient _tableClient;
    private const int TOKEN_EXPIRATION_DAYS = 90;

    public AzureTableTokenStore(string connectionString, string tableName)
    {
        _tableClient = new TableClient(connectionString, tableName);
        
        // Ensure table exists
        _tableClient.CreateIfNotExists();
        
        // Cleanup expired tokens on startup
        CleanupExpiredTokens();
    }

    private void CleanupExpiredTokens()
    {
        try
        {
            var expirationDate = DateTime.UtcNow;
            var expiredTokens = _tableClient.Query<TokenDataEntity>(
                filter: $"PartitionKey eq 'TokenCode' and ExpiresAt lt datetime'{expirationDate:yyyy-MM-ddTHH:mm:ssZ}'");
            
            foreach (var token in expiredTokens)
            {
                _tableClient.DeleteEntity(token.PartitionKey, token.RowKey);
            }
        }
        catch
        {
            // Ignore cleanup errors on startup
        }
    }

    public async Task StoreCodeData(TokenData codeData)
    {
        codeData.CreatedAt = DateTime.UtcNow;
        
        var entity = new TokenDataEntity
        {
            PartitionKey = "TokenCode", // Single partition for simplicity
            RowKey = codeData.Code,
            EntraRefreshToken = codeData.EntraRefreshToken,
            UserClaimsJson = codeData.UserClaims != null 
                ? JsonSerializer.Serialize(codeData.UserClaims) 
                : null,
            PkceStateJson = JsonSerializer.Serialize(codeData.PkceState),
            CreatedAt = codeData.CreatedAt,
            ExpiresAt = codeData.CreatedAt.AddDays(TOKEN_EXPIRATION_DAYS)
        };

        await _tableClient.UpsertEntityAsync(entity);
    }

    public async Task<TokenData?> GetAndConsumeCode(string code)
    {
        try
        {
            // Get the entity
            var response = await _tableClient.GetEntityAsync<TokenDataEntity>("TokenCode", code);
            var entity = response.Value;

            // Check expiration
            if (entity.ExpiresAt < DateTime.UtcNow)
            {
                // Delete expired token
                await _tableClient.DeleteEntityAsync("TokenCode", code, ETag.All);
                return null;
            }

            // Delete immediately (single-use)
            await _tableClient.DeleteEntityAsync("TokenCode", code, entity.ETag);

            // Deserialize and return
            var tokenData = new TokenData
            {
                Code = entity.RowKey,
                EntraRefreshToken = entity.EntraRefreshToken,
                UserClaims = entity.UserClaimsJson != null 
                    ? JsonSerializer.Deserialize<UserClaims>(entity.UserClaimsJson) 
                    : null,
                PkceState = JsonSerializer.Deserialize<PkceStateData>(entity.PkceStateJson)!,
                CreatedAt = entity.CreatedAt
            };

            return tokenData;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            // Code not found or already consumed
            return null;
        }
    }
}

/// <summary>
/// Azure Table entity for storing TokenData.
/// PartitionKey = "TokenCode" (single partition)
/// RowKey = Code (the single-use token code)
/// </summary>
public class TokenDataEntity : ITableEntity
{
    public string PartitionKey { get; set; } = default!;
    public string RowKey { get; set; } = default!;
    public DateTimeOffset? Timestamp { get; set; }
    public ETag ETag { get; set; }

    // TokenData properties
    public string EntraRefreshToken { get; set; } = default!;
    public string? UserClaimsJson { get; set; }
    public string PkceStateJson { get; set; } = default!;
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}
