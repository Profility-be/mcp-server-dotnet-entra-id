using Microsoft.Extensions.Primitives;

namespace MCP.Services;

/// <summary>
/// Extended configuration interface with typed helper methods.
/// Inherits from IConfiguration so it can be used as a drop-in replacement.
/// </summary>
public interface IAppConfiguration : IConfiguration
{
    int JwtExpirationMinutes { get; }
    int JwtExpirationSeconds { get; }
    string FullScope { get; }
    string OAuthCallbackUrl { get; }
    string EntraAuthorizationUrl { get; }
    string EntraTokenUrl { get; }
}

/// <summary>
/// Implementation of IAppConfiguration that wraps IConfiguration with typed accessors.
/// Prevents common configuration errors like trailing slashes and repeated conversions.
/// </summary>
public class AppConfiguration : IAppConfiguration
{
    private readonly IConfiguration _configuration;
    
    public AppConfiguration(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    // IConfiguration passthrough members with intelligent normalization
    public string? this[string key]
    {
        get
        {
            var value = _configuration[key];
            
            // Validate required configuration keys
            if (string.IsNullOrWhiteSpace(value))
            {
                // Required keys that must have a value
                if (key == "MCP:ServerUrl" || 
                    key == "AzureAd:TenantId" || 
                    key == "AzureAd:ClientId" || 
                    key == "AzureAd:ClientSecret")
                {
                    throw new InvalidOperationException($"Configuration '{key}' is required but not configured");
                }
                
                // Optional keys with defaults
                if (key == "OAuth:AllowedRedirectHost")
                {
                    return "claude.ai";
                }
                
                return value;
            }
            
            // Automatically normalize known configuration keys
            // Remove trailing slashes from URL configurations
            if (key == "MCP:ServerUrl")
            {
                return value.TrimEnd('/');
            }
            
            return value;
        }
        set => _configuration[key] = value;
    }

    public IEnumerable<IConfigurationSection> GetChildren() => _configuration.GetChildren();
    public IChangeToken GetReloadToken() => _configuration.GetReloadToken();
    public IConfigurationSection GetSection(string key) => _configuration.GetSection(key);

    // Typed configuration properties for complex logic only
    public int JwtExpirationMinutes
    {
        get
        {
            var minutes = _configuration["Jwt:ExpirationMinutes"];
            if (string.IsNullOrWhiteSpace(minutes))
            {
                return 60; // Default: 1 hour
            }

            if (!int.TryParse(minutes, out var minutesValue))
            {
                throw new InvalidOperationException($"Configuration 'Jwt:ExpirationMinutes' has invalid value: {minutes}");
            }

            return minutesValue;
        }
    }

    public int JwtExpirationSeconds => JwtExpirationMinutes * 60;

    public string FullScope
    {
        get
        {
            var baseScope = _configuration["AzureAd:Scope"];
            if (string.IsNullOrWhiteSpace(baseScope))
            {
                var clientId = this["AzureAd:ClientId"];  // Uses indexer with validation
                baseScope = $"api://{clientId}/MCP.Access";
            }
            
            return $"{baseScope} openid profile email offline_access";
        }
    }

    public string OAuthCallbackUrl => $"{this["MCP:ServerUrl"]}/oauth/callback";  // Uses indexer with normalization

    public string EntraAuthorizationUrl => $"https://login.microsoftonline.com/{this["AzureAd:TenantId"]}/oauth2/v2.0/authorize";  // Uses indexer with validation

    public string EntraTokenUrl => $"https://login.microsoftonline.com/{this["AzureAd:TenantId"]}/oauth2/v2.0/token";  // Uses indexer with validation
}
