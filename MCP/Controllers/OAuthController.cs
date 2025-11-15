using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text;
using MCP.Models;
using MCP.Services;
using MCP.Services.Jwt;
using Profility.MCP.Services.TokenStore;

namespace MCP.Controllers;

/// <summary>
/// OAuth 2.0 proxy controller that bridges Claude AI and Microsoft Entra ID.
/// Implements RFC 7591 (Dynamic Client Registration), RFC 7636 (PKCE), and RFC 8707 (Resource Indicators).
/// Note: Inherits from Controller (not ControllerBase) to support View rendering in Authorize endpoint.
/// </summary>
[Route("oauth")]
public class OAuthController : Controller
{
    private readonly IAppConfiguration _configuration;
    private readonly ILogger<OAuthController> _logger;
    private readonly IClientStore _clientStore;
    private readonly IPkceStateManager _stateManager;
    private readonly ITokenStore _tokenStore;
    private readonly ILoginTokenStore _loginTokenStore;
    private readonly IJwtBuilder _tokenGenerator;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IBrandingProvider _brandingProvider;

    public OAuthController(
        IAppConfiguration configuration,
        ILogger<OAuthController> logger,
        IClientStore clientStore,
        IPkceStateManager stateManager,
        ITokenStore tokenStore,
        ILoginTokenStore loginTokenStore,
        IJwtBuilder tokenGenerator,
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
        if (request == null) { return BadRequest(new { error = "invalid_request", error_description = "Request body is required and must be valid JSON" }); }

        try
        {
            if (request.RedirectUris == null || request.RedirectUris.Count == 0) { return BadRequest(new { error = "invalid_redirect_uri", error_description = "At least one redirect URI is required" }); }

            // Validate redirect URIs: only allow HTTPS and configured host (default: claude.ai)
            var allowedHost = _configuration["OAuth:AllowedRedirectHost"] ?? "claude.ai";
            foreach (var uriString in request.RedirectUris)
            {
                if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || !string.Equals(uri.Host, allowedHost, StringComparison.OrdinalIgnoreCase))
                {
                    return BadRequest(new { error = "invalid_redirect_uri", error_description = $"Redirect URI not allowed: {uriString}" });
                }
            }

            var proxyClientId = await _clientStore.RegisterClient(request.ClientName ?? "unknown", request.RedirectUris, request.Scope ?? "");

            return Ok(new
            {
                client_id = proxyClientId,
                client_name = request.ClientName,
                redirect_uris = request.RedirectUris,
                grant_types = request.GrantTypes ?? new List<string> { "authorization_code" },
                response_types = new[] { "code" },
                token_endpoint_auth_method = "none",
                client_id_issued_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            });
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
        try
        {
            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri) || string.IsNullOrEmpty(state) || string.IsNullOrEmpty(codeChallenge)) { return BadRequest(new { error = "invalid_request", error_description = "Missing required parameters" }); }
            if (responseType != "code") { return BadRequest(new { error = "unsupported_response_type", error_description = "Only 'code' response type is supported" }); }
            if (codeChallengeMethod != "S256") { return BadRequest(new { error = "invalid_request", error_description = "Only S256 code challenge method is supported" }); }

            var clientMapping = await _clientStore.GetClientMapping(clientId);
            if (clientMapping == null) { return BadRequest(new { error = "invalid_client", error_description = "Client not found" }); }

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

            var loginToken = await _loginTokenStore.CreateLoginToken(encryptedState);

            var model = new LoginPageModel { LoginToken = loginToken, IsExpired = false };
            var branding = _brandingProvider.Get();
            model.CompanyName = branding.CompanyName;
            model.ProductName = branding.ProductName;
            model.PrimaryColor = branding.PrimaryColor;
            model.PrimaryHoverColor = branding.PrimaryHoverColor;

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
        try
        {
            var loginData = await _loginTokenStore.GetAndConsumeLoginToken(token);
            if (loginData == null) { return BadRequest("Invalid or expired login token"); }

            var stateData = _stateManager.DecryptAndRetrieveState(loginData.EncryptedState);
            if (stateData == null) { return BadRequest("Invalid state data"); }

            // Build the Entra ID authorization URL
            var clientId = _configuration["AzureAd:ClientId"];
            var fullScope = _configuration.FullScope;
            var redirectUri = _configuration.OAuthCallbackUrl;

            var entraAuthUrl = _configuration.EntraAuthorizationUrl + 
                $"?client_id={Uri.EscapeDataString(clientId!)}" +
                $"&response_type=code" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&scope={Uri.EscapeDataString(fullScope)}" +
                $"&state={Uri.EscapeDataString(loginData.EncryptedState)}" +
                $"&code_challenge={Uri.EscapeDataString(stateData.ProxyCodeChallenge!)}" +  // Proxy's PKCE challenge for Entra ID
                $"&code_challenge_method=S256" +
                $"&prompt=select_account";

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
        try
        {
            var loginData = await _loginTokenStore.GetAndConsumeLoginToken(token);
            if (loginData == null) { return BadRequest("Invalid login token"); }

            var stateData = _stateManager.DecryptAndRetrieveState(loginData.EncryptedState);
            if (stateData == null) { return BadRequest("Invalid state data"); }

            var errorUrl = $"{stateData.RedirectUri}?error=access_denied&error_description={Uri.EscapeDataString("User canceled the login")}&state={Uri.EscapeDataString(stateData.OriginalState)}";

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
        try
        {
            if (!string.IsNullOrEmpty(error))
            {
                var stateData = _stateManager.DecryptAndRetrieveState(state ?? "");
                if (stateData != null) { return Redirect($"{stateData.RedirectUri}?error={error}&error_description={Uri.EscapeDataString(errorDescription ?? "")}&state={stateData.OriginalState}"); }
                return BadRequest(new { error, error_description = errorDescription });
            }

            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state)) { return BadRequest(new { error = "invalid_request", error_description = "Missing code or state parameter" }); }

            var pkceState = _stateManager.DecryptAndRetrieveState(state);
            if (pkceState == null) { return BadRequest(new { error = "invalid_request", error_description = "Invalid or expired state" }); }

            var tokenResponse = await CallEntraIdTokenEndpoint("authorization_code", pkceState, code: code);
            if (tokenResponse == null) { return Redirect($"{pkceState.RedirectUri}?error=server_error&error_description=Token exchange failed&state={pkceState.OriginalState}"); }

            if (string.IsNullOrEmpty(tokenResponse.RefreshToken))
            {
                _logger.LogError("Entra ID did not return a refresh token - check 'offline_access' scope");
                return Redirect($"{pkceState.RedirectUri}?error=server_error&error_description=No refresh token received&state={pkceState.OriginalState}");
            }

            var proxyAuthCode = _tokenGenerator.GenerateOpaqueToken();

            await _tokenStore.StoreCodeData(new TokenData
            {
                Code = proxyAuthCode,
                EntraRefreshToken = tokenResponse.RefreshToken,
                UserClaims = tokenResponse.UserClaims,
                PkceState = pkceState,
                CreatedAt = DateTime.UtcNow
            });

            _stateManager.RemoveState(state);

            return Redirect($"{pkceState.RedirectUri}?code={proxyAuthCode}&state={pkceState.OriginalState}");
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
    /// Handles both authorization_code and refresh_token grant types.
    /// </summary>
    [HttpPost("token")]
    public async Task<IActionResult> Token([FromForm] TokenRequest request)
    {
        try
        {
            // Step 1: Get and consume code (works for both grant types)
            string code;
            
            if (request.GrantType == "authorization_code")
            {
                if (string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.CodeVerifier)) { return BadRequest(new { error = "invalid_request", error_description = "Missing code or code_verifier" }); }
                code = request.Code;
            }
            else if (request.GrantType == "refresh_token")
            {
                if (string.IsNullOrEmpty(request.RefreshToken)) { return BadRequest(new { error = "invalid_request", error_description = "Missing refresh_token" }); }
                code = request.RefreshToken;
            }
            else
            {
                return BadRequest(new { error = "unsupported_grant_type", error_description = $"Grant type '{request.GrantType}' is not supported" });
            }

            var tokenData = await _tokenStore.GetAndConsumeCode(code);
            if (tokenData == null) { return BadRequest(new { error = "invalid_grant", error_description = "Code is invalid or has already been used" }); }

            // Step 2: Validate PKCE (only for authorization_code)
            if (request.GrantType == "authorization_code")
            {
                if (!_tokenGenerator.ValidateCodeVerifier(request.CodeVerifier!, tokenData.PkceState.CodeChallenge)) { return BadRequest(new { error = "invalid_grant", error_description = "Invalid code_verifier" }); }
            }

            // Step 3: Refresh Entra tokens if needed (for refresh_token grant)
            string entraRefreshToken = tokenData.EntraRefreshToken;
            
            if (request.GrantType == "refresh_token")
            {
                var newTokens = await CallEntraIdTokenEndpoint("refresh_token", tokenData.PkceState, refreshToken: entraRefreshToken);
                if (newTokens == null) { return BadRequest(new { error = "invalid_grant", error_description = "Failed to refresh tokens" }); }
                
                if (!string.IsNullOrEmpty(newTokens.RefreshToken)) { entraRefreshToken = newTokens.RefreshToken; }
            }

            var jwtToken = _tokenGenerator.BuildJwt(tokenData.PkceState.ClientId, tokenData.UserClaims?.GetIdentifier() ?? "unknown", tokenData.PkceState.Scope ?? "", tokenData.UserClaims);

            var newCode = _tokenGenerator.GenerateOpaqueToken();
            await _tokenStore.StoreCodeData(new TokenData
            {
                Code = newCode,
                EntraRefreshToken = entraRefreshToken,
                UserClaims = tokenData.UserClaims,
                PkceState = tokenData.PkceState,
                CreatedAt = DateTime.UtcNow
            });

            var expirationTimeUtc = DateTime.UtcNow.AddSeconds(_configuration.JwtExpirationSeconds);
            var minutes = Math.Round(_configuration.JwtExpirationSeconds / 60.0);
            _logger.LogInformation("Token issued with grant_type {GrantType}, expires at {ExpirationTimeUtc:yyyy-MM-dd HH:mm:ss} UTC, expires in {Minutes} minutes", request.GrantType, expirationTimeUtc, minutes);

            return Ok(new
            {
                access_token = jwtToken,
                token_type = "Bearer",
                expires_in = _configuration.JwtExpirationSeconds,
                refresh_token = newCode,
                scope = tokenData.PkceState.Scope
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token exchange");
            return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
        }
    }

    private async Task<EntraTokenResponse?> CallEntraIdTokenEndpoint(string grantType, PkceStateData stateData, string? code = null, string? refreshToken = null)
    {
        try
        {
            var clientId = _configuration["AzureAd:ClientId"];
            var clientSecret = _configuration["AzureAd:ClientSecret"];
            var tokenEndpoint = _configuration.EntraTokenUrl;

            var formData = new Dictionary<string, string>
            {
                ["client_id"] = clientId!,
                ["client_secret"] = clientSecret!,
                ["grant_type"] = grantType
            };

            if (grantType == "authorization_code")
            {
                formData["code"] = code!;
                formData["redirect_uri"] = _configuration.OAuthCallbackUrl;
                formData["code_verifier"] = stateData.ProxyCodeVerifier ?? "";
            }
            else if (grantType == "refresh_token")
            {
                formData["refresh_token"] = refreshToken!;
                formData["scope"] = stateData.Scope ?? "";
            }

            var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(formData));

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Entra ID token request failed: grant_type={GrantType}, status={StatusCode}", grantType, response.StatusCode);
                return null;
            }

            var content = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<EntraIdTokenResponse>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (tokenResponse == null) { return null; }
            
            var userClaims = grantType == "authorization_code" 
                ? (!string.IsNullOrEmpty(tokenResponse.IdToken) ? ExtractUserClaimsFromToken(tokenResponse.IdToken) : ExtractUserClaimsFromToken(tokenResponse.AccessToken))
                : null;

            return new EntraTokenResponse
            {
                AccessToken = tokenResponse.AccessToken,
                IdToken = tokenResponse.IdToken,
                RefreshToken = tokenResponse.RefreshToken,
                ExpiresIn = tokenResponse.ExpiresIn,
                UserClaims = userClaims
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during Entra ID token request: grant_type={GrantType}", grantType);
            return null;
        }
    }

    private UserClaims? ExtractUserClaimsFromToken(string accessToken)
    {
        try
        {
            var parts = accessToken.Split('.');
            if (parts.Length != 3) { return null; }

            var payload = parts[1];
            var padding = (4 - (payload.Length % 4)) % 4;
            payload = payload.PadRight(payload.Length + padding, '=');

            var bytes = Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'));
            var json = Encoding.UTF8.GetString(bytes);
            
            var claimsDict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            if (claimsDict == null) { return null; }

            var userClaims = new UserClaims();

            if (claimsDict.TryGetValue("oid", out var oid)) { userClaims.ObjectId = oid.GetString(); }
            if (claimsDict.TryGetValue("sub", out var sub)) { userClaims.Subject = sub.GetString(); }
            if (claimsDict.TryGetValue("name", out var name)) { userClaims.Name = name.GetString(); }
            if (claimsDict.TryGetValue("email", out var email)) { userClaims.Email = email.GetString(); }
            if (claimsDict.TryGetValue("preferred_username", out var preferredUsername)) { userClaims.PreferredUsername = preferredUsername.GetString(); }
            if (claimsDict.TryGetValue("upn", out var upn)) { userClaims.Upn = upn.GetString(); }
            else { userClaims.Upn = userClaims.PreferredUsername ?? userClaims.Email; }
            if (claimsDict.TryGetValue("tid", out var tid)) { userClaims.TenantId = tid.GetString(); }
            if (claimsDict.TryGetValue("given_name", out var givenName)) { userClaims.GivenName = givenName.GetString(); }
            if (claimsDict.TryGetValue("family_name", out var familyName)) { userClaims.FamilyName = familyName.GetString(); }
            
            return userClaims;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception while extracting user claims from access token");
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
    public string? IdToken { get; set; }  // Add ID token
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
