using Microsoft.AspNetCore.Mvc;

namespace MCP.Controllers;

/// <summary>
/// Implements OAuth 2.0 discovery endpoints per RFC 9728 and RFC 8414.
/// These endpoints tell Claude where to find the authorization server and how to authenticate.
/// </summary>
[ApiController]
public class WellKnownController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<WellKnownController> _logger;

    public WellKnownController(IConfiguration configuration, ILogger<WellKnownController> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// RFC 9728: OAuth 2.0 Protected Resource Metadata
    /// This tells Claude that this MCP server requires OAuth authentication
    /// and points to the authorization server.
    /// </summary>
    [HttpGet(".well-known/oauth-protected-resource")]
    public IActionResult GetProtectedResourceMetadata()
    {
        var baseUrl = _configuration["MCP:ServerUrl"]?.TrimEnd('/');
        var clientId = _configuration["AzureAd:ClientId"];
        
        _logger.LogInformation("Protected resource metadata requested from {BaseUrl}", baseUrl);

        var metadata = new
        {
            // The MCP server URL (this resource)
            resource = baseUrl,
            
            // The authorization server (the OAuth proxy itself, not Entra ID)
            authorization_servers = new[] { baseUrl },
            
            // Supported scopes
            scopes_supported = new[] 
            { 
                $"api://{clientId}/MCP.Access",
                "openid",
                "profile",
                "email"
            },
            
            // How to send the bearer token
            bearer_methods_supported = new[] { "header" },
            
            // Token types accepted
            resource_documentation = $"{baseUrl}/docs"
        };

        return Ok(metadata);
    }

    /// <summary>
    /// RFC 8414: OAuth 2.0 Authorization Server Metadata
    /// This tells Claude about the OAuth endpoints and capabilities.
    /// The proxy acts as the authorization server from Claude's perspective.
    /// </summary>
    [HttpGet(".well-known/oauth-authorization-server")]
    public IActionResult GetAuthorizationServerMetadata()
    {
        var baseUrl = _configuration["MCP:ServerUrl"]?.TrimEnd('/');
        
        _logger.LogInformation("Authorization server metadata requested from {BaseUrl}", baseUrl);

        var metadata = new
        {
            // The issuer identifier (the proxy itself)
            issuer = baseUrl,
            
            // OAuth endpoints
            authorization_endpoint = $"{baseUrl}/oauth/authorize",
            token_endpoint = $"{baseUrl}/oauth/token",
            registration_endpoint = $"{baseUrl}/oauth/register",
            
            // Supported grant types
            grant_types_supported = new[] 
            { 
                "authorization_code",
                "refresh_token" 
            },
            
            // Response types
            response_types_supported = new[] { "code" },
            
            // PKCE support (MANDATORY for Claude)
            code_challenge_methods_supported = new[] { "S256" },
            
            // Token endpoint authentication methods
            token_endpoint_auth_methods_supported = new[] 
            { 
                "none",           // For public clients (Claude)
                "client_secret_post",
                "client_secret_basic"
            },
            
            // Supported scopes
            scopes_supported = new[] 
            { 
                $"api://{_configuration["AzureAd:ClientId"]}/MCP.Access",
                "openid",
                "profile", 
                "email"
            },
            
            // Claims supported
            claims_supported = new[]
            {
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "jti",
                "client_id",
                "scope"
            },
            
            // Service documentation
            service_documentation = $"{baseUrl}/docs",
            
            // UI locales supported
            ui_locales_supported = new[] { "en-US", "nl-BE", "fr-BE" }
        };

        return Ok(metadata);
    }

    /// <summary>
    /// OpenID Connect Discovery (bonus - some clients expect this)
    /// </summary>
    [HttpGet(".well-known/openid-configuration")]
    public IActionResult GetOpenIdConfiguration()
    {
        // Redirect to OAuth authorization server metadata
        return RedirectToAction(nameof(GetAuthorizationServerMetadata));
    }
}
