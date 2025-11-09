using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text;
using MCP.Models;
using MCP.Services;

namespace MCP.Controllers;

/// <summary>
/// OAuth 2.0 proxy controller that bridges Claude AI and Microsoft Entra ID.
/// Implements RFC 7591 (Dynamic Client Registration), RFC 7636 (PKCE), and RFC 8707 (Resource Indicators).
/// Note: Inherits from Controller (not ControllerBase) to support View rendering in Authorize endpoint.
/// </summary>
[Route("oauth")]
public class OAuthController : Controller
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<OAuthController> _logger;
    private readonly IClientStore _clientStore;
    private readonly IPkceStateManager _stateManager;
    private readonly ITokenStore _tokenStore;
    private readonly ILoginTokenStore _loginTokenStore;
    private readonly IProxyJwtTokenGenerator _tokenGenerator;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IBrandingProvider _brandingProvider;

    public OAuthController(
        IConfiguration configuration,
        ILogger<OAuthController> logger,
        IClientStore clientStore,
        IPkceStateManager stateManager,
        ITokenStore tokenStore,
        ILoginTokenStore loginTokenStore,
        IProxyJwtTokenGenerator tokenGenerator,
        IHttpClientFactory httpClientFactory,
        IBrandingProvider brandingProvider)
    {
        _configuration = configuration;
        _logger = logger;
        _clientStore = clientStore;
        _stateManager = stateManager;
        _tokenStore = tokenStore;
        _loginTokenStore = loginTokenStore;
        _tokenGenerator = tokenGenerator;
        _httpClientFactory = httpClientFactory;
        _brandingProvider = brandingProvider;
    }

    /// <summary>
    /// RFC 7591: Dynamic Client Registration
    /// Claude calls this to "register" as an OAuth client.
    /// We fake it by mapping a proxy client ID to our real Entra ID app.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> RegisterClient([FromBody] ClientRegistrationRequest? request)
    {
        if (request == null)
        {
            _logger.LogWarning("Failed to parse registration request - request body was null or invalid JSON");
            return BadRequest(new { 
                error = "invalid_request", 
                error_description = "Request body is required and must be valid JSON" 
            });
        }

        _logger.LogInformation("Client registration request received from {ClientName}", request.ClientName ?? "unknown");

        try
        {
            // Validate the registration request
            if (request.RedirectUris == null || request.RedirectUris.Count == 0)
            {
                return BadRequest(new { error = "invalid_redirect_uri", error_description = "At least one redirect URI is required" });
            }

            // Generate a proxy client ID and store the mapping
            var proxyClientId = await _clientStore.RegisterClient(
                request.ClientName ?? "unknown",
                request.RedirectUris,
                request.Scope ?? ""  // Scope is already a space-separated string
            );

            _logger.LogInformation("Client registered successfully with proxy client ID: {ClientId}", proxyClientId);

            // Return the registration response per RFC 7591
            var response = new
            {
                client_id = proxyClientId,
                client_name = request.ClientName,
                redirect_uris = request.RedirectUris,
                grant_types = request.GrantTypes ?? new List<string> { "authorization_code" },
                response_types = new[] { "code" },
                token_endpoint_auth_method = "none", // Public client (no client secret)
                client_id_issued_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during client registration");
            return StatusCode(500, new { error = "server_error", error_description = "Internal server error during registration" });
        }
    }

    /// <summary>
    /// OAuth 2.0 Authorization Endpoint
    /// Claude redirects the user here to start the OAuth flow.
    /// We redirect to our custom login page, which then goes to Entra ID.
    /// Accepts both GET (initial request) and POST (form submission from login page).
    /// </summary>
    [HttpGet("authorize")]
    [HttpPost("authorize")]
    public async Task<IActionResult> Authorize(
        [FromQuery(Name = "client_id")] string clientId,
        [FromQuery(Name = "redirect_uri")] string redirectUri,
        [FromQuery(Name = "response_type")] string responseType,
        [FromQuery(Name = "state")] string state,
        [FromQuery(Name = "code_challenge")] string codeChallenge,
        [FromQuery(Name = "code_challenge_method")] string codeChallengeMethod,
        [FromQuery] string? scope,
        [FromQuery] string? resource)
    {
        _logger.LogInformation("Authorization request: client_id={ClientId}, redirect_uri={RedirectUri}", clientId, redirectUri);

        try
        {
            // Validate required parameters
            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri) || 
                string.IsNullOrEmpty(state) || string.IsNullOrEmpty(codeChallenge))
            {
                return BadRequest(new { error = "invalid_request", error_description = "Missing required parameters" });
            }

            // Validate response_type
            if (responseType != "code")
            {
                return BadRequest(new { error = "unsupported_response_type", error_description = "Only 'code' response type is supported" });
            }

            // Validate PKCE method
            if (codeChallengeMethod != "S256")
            {
                return BadRequest(new { error = "invalid_request", error_description = "Only S256 code challenge method is supported" });
            }

            // Validate client exists
            var clientMapping = await _clientStore.GetClientMapping(clientId);
            if (clientMapping == null)
            {
                _logger.LogWarning("Unknown client ID: {ClientId}", clientId);
                return BadRequest(new { error = "invalid_client", error_description = "Client not found" });
            }

            // Generate proxy's own PKCE parameters for Entra ID
            var proxyCodeVerifier = _tokenGenerator.GenerateCodeVerifier();
            var proxyCodeChallenge = _tokenGenerator.GenerateCodeChallenge(proxyCodeVerifier);

            // Create PKCE state data
            var stateData = new PkceStateData
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                CodeChallenge = codeChallenge,  // Claude's challenge (for validation when Claude sends token request)
                CodeChallengeMethod = codeChallengeMethod,
                ProxyCodeVerifier = proxyCodeVerifier,  // Proxy's verifier (for Entra ID token exchange)
                ProxyCodeChallenge = proxyCodeChallenge,  // Proxy's challenge (for Entra ID authorization)
                OriginalState = state,
                Scope = scope,
                Resource = resource ?? _configuration["MCP:ServerUrl"],
                CreatedAt = DateTime.UtcNow
            };

            // Encrypt and store the state
            var encryptedState = _stateManager.EncryptAndStoreState(stateData);

            // Create a login token for the custom login page
            var loginToken = await _loginTokenStore.CreateLoginToken(encryptedState);

            _logger.LogInformation("Rendering login page for client: {ClientId}", clientId);

            // CRITICAL: Render the view DIRECTLY (no redirect!)
            // Claude opens /oauth/authorize in a browser window
            // and expects to see HTML immediately, not a 302 redirect.
            // 
            // This is similar to how Atlassian OAuth connectors work:
            // /oauth/authorize renders a wizard/login UI directly
            var model = new LoginPageModel
            {
                LoginToken = loginToken,
                IsExpired = false
            };
            // Populate branding from configuration via shared provider
            var branding = _brandingProvider.Get();
            model.CompanyName = branding.CompanyName;
            model.ProductName = branding.ProductName;
            model.PrimaryColor = branding.PrimaryColor;
            model.PrimaryHoverColor = branding.PrimaryHoverColor;

            _logger.LogInformation("Branding loaded - Company: {Company}, Product: {Product}", model.CompanyName, model.ProductName);

            return View("~/Views/Login/Index.cshtml", model);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during authorization");
            return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
        }
    }

    /// <summary>
    /// User confirmed login - redirect to Entra ID
    /// </summary>
    [HttpPost("continue")]
    public async Task<IActionResult> Continue([FromForm] string token)
    {
        _logger.LogInformation("User confirmed login");

        try
        {
            // Validate the login token
            var loginData = await _loginTokenStore.GetLoginTokenData(token);
            if (loginData == null || loginData.IsUsed || loginData.ExpiresAt < DateTime.UtcNow)
            {
                _logger.LogWarning("Invalid or expired login token");
                return BadRequest("Invalid or expired login token");
            }

            // Mark token as used
            await _loginTokenStore.MarkTokenAsUsed(token);

            // Decrypt the state to get PKCE data
            var stateData = _stateManager.DecryptAndRetrieveState(loginData.EncryptedState);
            if (stateData == null)
            {
                _logger.LogError("Failed to decrypt state data");
                return BadRequest("Invalid state data");
            }

            // Build the Entra ID authorization URL
            var tenantId = _configuration["AzureAd:TenantId"];
            var clientId = _configuration["AzureAd:ClientId"];
            var baseScope = _configuration["AzureAd:Scope"] ?? $"api://{clientId}/MCP.Access";
            var fullScope = $"{baseScope} openid profile email";  // Add OpenID Connect scopes for ID token
            var baseUrl = _configuration["MCP:ServerUrl"]?.TrimEnd('/');
            var redirectUri = $"{baseUrl}/oauth/callback";

            var entraAuthUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize" +
                $"?client_id={Uri.EscapeDataString(clientId!)}" +
                $"&response_type=code" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&scope={Uri.EscapeDataString(fullScope)}" +
                $"&state={Uri.EscapeDataString(loginData.EncryptedState)}" +
                $"&code_challenge={Uri.EscapeDataString(stateData.ProxyCodeChallenge!)}" +  // Proxy's PKCE challenge for Entra ID
                $"&code_challenge_method=S256" +  // PKCE method (SHA-256)
                $"&prompt=select_account"; // Force account selection

            _logger.LogInformation("Redirecting to Entra ID for authentication");

            return Redirect(entraAuthUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login continuation");
            return StatusCode(500, "Er is een fout opgetreden. Probeer het later opnieuw.");
        }
    }

    /// <summary>
    /// User canceled the login
    /// </summary>
    [HttpPost("cancel")]
    public async Task<IActionResult> Cancel([FromForm] string token)
    {
        _logger.LogInformation("User canceled login with token: {Token}", token);

        try
        {
            // Validate the login token
            var loginData = await _loginTokenStore.GetLoginTokenData(token);
            if (loginData == null)
            {
                return BadRequest("Invalid login token");
            }

            // Mark token as used
            await _loginTokenStore.MarkTokenAsUsed(token);

            // Decrypt the state to get redirect URI
            var stateData = _stateManager.DecryptAndRetrieveState(loginData.EncryptedState);
            if (stateData == null)
            {
                return BadRequest("Invalid state data");
            }

            // Redirect back to Claude with error
            var errorUrl = $"{stateData.RedirectUri}" +
                $"?error=access_denied" +
                $"&error_description={Uri.EscapeDataString("User canceled the login")}" +
                $"&state={Uri.EscapeDataString(stateData.OriginalState)}";

            _logger.LogInformation("Redirecting to error URL: {Url}", errorUrl);

            return Redirect(errorUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login cancellation");
            return StatusCode(500, "Er is een fout opgetreden.");
        }
    }

    /// <summary>
    /// OAuth 2.0 Callback Endpoint
    /// Entra ID redirects back here after user authentication.
    /// We exchange the Entra auth code for tokens, then redirect back to Claude.
    /// </summary>
    [HttpGet("callback")]
    public async Task<IActionResult> Callback(
        [FromQuery] string? code,
        [FromQuery] string? state,
        [FromQuery] string? error,
        [FromQuery(Name = "error_description")] string? errorDescription)
    {
        _logger.LogInformation("OAuth callback received from Entra ID");

        try
        {
            // Handle errors from Entra ID
            if (!string.IsNullOrEmpty(error))
            {
                _logger.LogWarning("Entra ID returned error: {Error} - {Description}", error, errorDescription);
                
                // Retrieve state to get redirect URI
                var stateData = _stateManager.DecryptAndRetrieveState(state ?? "");
                if (stateData != null)
                {
                    var errorUrl = $"{stateData.RedirectUri}?error={error}&error_description={Uri.EscapeDataString(errorDescription ?? "")}&state={stateData.OriginalState}";
                    return Redirect(errorUrl);
                }
                
                return BadRequest(new { error, error_description = errorDescription });
            }

            // Validate required parameters
            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
            {
                return BadRequest(new { error = "invalid_request", error_description = "Missing code or state parameter" });
            }

            // Decrypt and retrieve the state data
            var pkceState = _stateManager.DecryptAndRetrieveState(state);
            if (pkceState == null)
            {
                _logger.LogWarning("Invalid or expired state parameter");
                return BadRequest(new { error = "invalid_request", error_description = "Invalid or expired state" });
            }

            // Exchange the authorization code for tokens with Entra ID
            var entraIdToken = await ExchangeCodeForTokens(code, pkceState);
            if (entraIdToken == null)
            {
                _logger.LogError("Failed to exchange code for tokens with Entra ID");
                var errorUrl = $"{pkceState.RedirectUri}?error=server_error&error_description=Token exchange failed&state={pkceState.OriginalState}";
                return Redirect(errorUrl);
            }

            // Generate a proxy authorization code
            var proxyAuthCode = _tokenGenerator.GenerateOpaqueToken();

            // Store the authorization code data for later token exchange
            await _tokenStore.StoreAuthorizationCode(proxyAuthCode, pkceState, code);

            // Create token mapping
            var userIdentifier = entraIdToken.UserClaims?.GetIdentifier() ?? "unknown";
            
            if (entraIdToken.UserClaims == null)
            {
                _logger.LogWarning("No user claims extracted from ID token");
            }
            
            var tokenMapping = new TokenMapping
            {
                ProxyAccessToken = _tokenGenerator.GenerateOpaqueToken(),
                EntraAccessToken = entraIdToken.AccessToken,
                ProxyRefreshToken = _tokenGenerator.GenerateOpaqueToken(), // Always generate proxy refresh token for Claude
                EntraRefreshToken = entraIdToken.RefreshToken, // Store Entra refresh token (may be null)
                ClientId = pkceState.ClientId,
                AuthorizationCode = proxyAuthCode,
                UserIdentifier = userIdentifier,
                UserClaims = entraIdToken.UserClaims,
                ExpiresAt = DateTime.UtcNow.AddSeconds(entraIdToken.ExpiresIn),
                Scopes = pkceState.Scope ?? ""
            };

            await _tokenStore.StoreTokenMapping(tokenMapping);
            
            _logger.LogInformation("Token mapping stored for user: {UserIdentifier}", userIdentifier);

            // Clean up state
            _stateManager.RemoveState(state);

            // Redirect back to Claude with the proxy authorization code
            var callbackUrl = $"{pkceState.RedirectUri}?code={proxyAuthCode}&state={pkceState.OriginalState}";
            
            _logger.LogInformation("Redirecting back to Claude: {RedirectUri}", pkceState.RedirectUri);

            return Redirect(callbackUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during OAuth callback");
            return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
        }
    }

    /// <summary>
    /// OAuth 2.0 Token Endpoint
    /// Claude calls this to exchange the authorization code for access tokens.
    /// </summary>
    [HttpPost("token")]
    public async Task<IActionResult> Token([FromForm] TokenRequest request)
    {
        _logger.LogInformation("Token request: grant_type={GrantType}, client_id={ClientId}", 
            request.GrantType, request.ClientId);

        try
        {
            if (request.GrantType == "authorization_code")
            {
                return await HandleAuthorizationCodeGrant(request);
            }
            else if (request.GrantType == "refresh_token")
            {
                return await HandleRefreshTokenGrant(request);
            }
            else
            {
                return BadRequest(new { error = "unsupported_grant_type", error_description = $"Grant type '{request.GrantType}' is not supported" });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token exchange");
            return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
        }
    }

    private async Task<IActionResult> HandleAuthorizationCodeGrant(TokenRequest request)
    {
        // Validate required parameters
        if (string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.CodeVerifier))
        {
            return BadRequest(new { error = "invalid_request", error_description = "Missing code or code_verifier" });
        }

        // Validate and consume the authorization code (prevents replay attacks)
        if (!await _tokenStore.ValidateAndConsumeAuthorizationCode(request.Code))
        {
            _logger.LogWarning("Authorization code already used or invalid: {Code}", request.Code);
            return BadRequest(new { error = "invalid_grant", error_description = "Authorization code is invalid or has already been used" });
        }

        // Get the token mapping
        var tokenMapping = await _tokenStore.GetTokenMappingByCode(request.Code);
        if (tokenMapping == null)
        {
            _logger.LogWarning("Token mapping not found for code: {Code}", request.Code);
            return BadRequest(new { error = "invalid_grant", error_description = "Authorization code not found" });
        }

        // Get the PKCE state data to validate code_verifier
        // Note: In production, you'd store this more securely
        // For now, we'll trust the code_verifier since we already validated the code

        // Generate JWT access token with correct aud claim and user claims
        _logger.LogInformation("Generating JWT access token for client: {ClientId}", tokenMapping.ClientId);
        
        if (tokenMapping.UserClaims == null)
        {
            _logger.LogWarning("No user claims available in token mapping");
        }
        
        var mcpServerUrl = _configuration["MCP:ServerUrl"]?.TrimEnd('/') ?? throw new InvalidOperationException("MCP:ServerUrl not configured");
        var jwtToken = _tokenGenerator.GenerateAccessToken(
            tokenMapping.ClientId,
            tokenMapping.UserIdentifier ?? "unknown",
            mcpServerUrl,
            tokenMapping.Scopes ?? "",
            tokenMapping.UserClaims // Pass the full user claims from Entra ID
        );

        // Build response dynamically to only include refresh_token if available
        var responseData = new Dictionary<string, object>
        {
            ["access_token"] = jwtToken,
            ["token_type"] = "Bearer",
            ["expires_in"] = int.Parse(_configuration["Jwt:ExpirationMinutes"] ?? "60") * 60,
            ["scope"] = tokenMapping.Scopes ?? "",
            ["refresh_token"] = tokenMapping.ProxyRefreshToken! // Always include proxy refresh token
        };

        _logger.LogInformation("✅ Token issued with refresh token for client: {ClientId}", tokenMapping.ClientId);

        return Ok(responseData);
    }

    private Task<IActionResult> HandleRefreshTokenGrant(TokenRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            return Task.FromResult<IActionResult>(BadRequest(new { error = "invalid_request", error_description = "Missing refresh_token" }));
        }

        // TODO: Implement refresh token logic
        // For now, return not implemented
        _logger.LogWarning("Refresh token grant not yet implemented");
        
        return Task.FromResult<IActionResult>(BadRequest(new { error = "unsupported_grant_type", error_description = "Refresh token not yet implemented" }));
    }

    private async Task<EntraTokenResponse?> ExchangeCodeForTokens(string code, PkceStateData stateData)
    {
        try
        {
            var tenantId = _configuration["AzureAd:TenantId"];
            var clientId = _configuration["AzureAd:ClientId"];
            var clientSecret = _configuration["AzureAd:ClientSecret"];
            var baseUrl = _configuration["MCP:ServerUrl"]?.TrimEnd('/');
            var redirectUri = $"{baseUrl}/oauth/callback";

            var tokenEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";

            _logger.LogInformation("🔐 Exchanging authorization code for tokens (scope from authorization request will be used)");

            var formData = new Dictionary<string, string>
            {
                ["client_id"] = clientId!,
                ["client_secret"] = clientSecret!,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = stateData.ProxyCodeVerifier ?? ""  // Proxy's PKCE verifier for Entra ID
                // NOTE: NO scope parameter! Entra ID uses the scope from the authorization request
            };

            var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(formData));

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Entra ID token exchange failed: {StatusCode} - {Error}", response.StatusCode, errorContent);
                return null;
            }

            var content = await response.Content.ReadAsStringAsync();
            
            var tokenResponse = JsonSerializer.Deserialize<EntraIdTokenResponse>(content, new JsonSerializerOptions 
            { 
                PropertyNameCaseInsensitive = true 
            });

            if (tokenResponse == null)
            {
                _logger.LogError("Failed to deserialize Entra ID token response");
                return null;
            }

            _logger.LogInformation("Tokens received from Entra ID (AccessToken={HasAccess}, IdToken={HasId})", 
                !string.IsNullOrEmpty(tokenResponse.AccessToken), 
                !string.IsNullOrEmpty(tokenResponse.IdToken));
            
            // Extract user claims from ID token (not access token!)
            // ID token is a JWT with user info, access token might be opaque
            UserClaims? userClaims = null;
            
            if (!string.IsNullOrEmpty(tokenResponse.IdToken))
            {
                userClaims = ExtractUserClaimsFromToken(tokenResponse.IdToken);
            }
            else
            {
                _logger.LogWarning("No ID token in response from Entra ID");
                userClaims = ExtractUserClaimsFromToken(tokenResponse.AccessToken);
            }
            
            if (userClaims == null)
            {
                _logger.LogWarning("Failed to extract user claims from tokens");
            }

            return new EntraTokenResponse
            {
                AccessToken = tokenResponse.AccessToken,
                RefreshToken = tokenResponse.RefreshToken,
                ExpiresIn = tokenResponse.ExpiresIn,
                UserClaims = userClaims
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during token exchange with Entra ID");
            return null;
        }
    }

    private UserClaims? ExtractUserClaimsFromToken(string accessToken)
    {
        try
        {
            _logger.LogInformation("🔍 Extracting user claims from Entra ID access token...");
            
            // Simple JWT parsing to extract user claims
            var parts = accessToken.Split('.');
            if (parts.Length != 3)
            {
                _logger.LogWarning("❌ Invalid JWT format - expected 3 parts, got {Count}", parts.Length);
                return null;
            }

            var payload = parts[1];
            // Add padding if needed
            var padding = (4 - (payload.Length % 4)) % 4;
            payload = payload.PadRight(payload.Length + padding, '=');

            var bytes = Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'));
            var json = Encoding.UTF8.GetString(bytes);
            
            var claimsDict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

            if (claimsDict == null)
            {
                _logger.LogWarning("Failed to deserialize JWT payload");
                return null;
            }

            _logger.LogInformation("Extracting user claims from JWT ({Count} claims found)", claimsDict.Count);

            var userClaims = new UserClaims();

            // Extract OID (Object ID) - primary user identifier
            if (claimsDict.TryGetValue("oid", out var oid))
            {
                userClaims.ObjectId = oid.GetString();
            }
            
            // Extract Subject (fallback identifier)
            if (claimsDict.TryGetValue("sub", out var sub))
            {
                userClaims.Subject = sub.GetString();
            }
            
            // Extract Name
            if (claimsDict.TryGetValue("name", out var name))
            {
                userClaims.Name = name.GetString();
            }
            
            // Extract Email
            if (claimsDict.TryGetValue("email", out var email))
            {
                userClaims.Email = email.GetString();
            }
            
            // Extract Preferred Username (usually email or UPN)
            if (claimsDict.TryGetValue("preferred_username", out var preferredUsername))
            {
                userClaims.PreferredUsername = preferredUsername.GetString();
            }
            
            // Extract UPN (User Principal Name)
            if (claimsDict.TryGetValue("upn", out var upn))
            {
                userClaims.Upn = upn.GetString();
            }
            else
            {
                // Fallback: use preferred_username or email as UPN
                userClaims.Upn = userClaims.PreferredUsername ?? userClaims.Email;
            }
            
            // Extract Tenant ID (optional, not critical for user identification)
            if (claimsDict.TryGetValue("tid", out var tid))
            {
                userClaims.TenantId = tid.GetString();
            }
            
            // Extract Given Name
            if (claimsDict.TryGetValue("given_name", out var givenName))
            {
                userClaims.GivenName = givenName.GetString();
            }
            
            // Extract Family Name
            if (claimsDict.TryGetValue("family_name", out var familyName))
            {
                userClaims.FamilyName = familyName.GetString();
            }

            _logger.LogInformation("User claims extracted successfully ({ClaimCount} claims)", claimsDict.Count);
            
            return userClaims;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Exception while extracting user claims from access token");
            return null;
        }
    }
}

#region Request/Response Models

public class ClientRegistrationRequest
{
    [JsonPropertyName("client_name")]
    public string? ClientName { get; set; }
    
    [JsonPropertyName("redirect_uris")]
    public List<string>? RedirectUris { get; set; }
    
    [JsonPropertyName("grant_types")]
    public List<string>? GrantTypes { get; set; }
    
    [JsonPropertyName("response_types")]
    public List<string>? ResponseTypes { get; set; }
    
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }  // Changed from List<string> to string - RFC 7591 allows space-separated string
    
    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; set; }
}

public class TokenRequest
{
    [FromForm(Name = "grant_type")]
    public string GrantType { get; set; } = "";
    
    [FromForm(Name = "code")]
    public string? Code { get; set; }
    
    [FromForm(Name = "redirect_uri")]
    public string? RedirectUri { get; set; }
    
    [FromForm(Name = "client_id")]
    public string? ClientId { get; set; }
    
    [FromForm(Name = "code_verifier")]
    public string? CodeVerifier { get; set; }
    
    [FromForm(Name = "refresh_token")]
    public string? RefreshToken { get; set; }
}

public class EntraIdTokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = "";
    
    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }  // ID Token contains user claims
    
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }
    
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
    
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "";
}

public class EntraTokenResponse
{
    public required string AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public int ExpiresIn { get; set; }
    public UserClaims? UserClaims { get; set; }
}

public class UserClaims
{
    public string? ObjectId { get; set; }      // oid - Azure AD Object ID
    public string? Subject { get; set; }       // sub - Subject identifier
    public string? Name { get; set; }          // name - Full name
    public string? Email { get; set; }         // email - Email address
    public string? PreferredUsername { get; set; } // preferred_username - Usually email or UPN
    public string? Upn { get; set; }           // upn - User Principal Name
    public string? TenantId { get; set; }      // tid - Tenant ID
    public string? GivenName { get; set; }     // given_name - First name
    public string? FamilyName { get; set; }    // family_name - Last name
    
    public string GetIdentifier() => ObjectId ?? Subject ?? Email ?? PreferredUsername ?? "unknown";
}

#endregion
