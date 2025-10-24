using Microsoft.AspNetCore.Mvc;
using MCP.Models;
using MCP.Services;

namespace MCP.Controllers;

/// <summary>
/// Custom login page controller for the OAuth proxy.
/// Shows users a consent page before redirecting to Entra ID.
/// </summary>
[Route("Login")]
public class LoginController : Controller
{
    private readonly ILogger<LoginController> _logger;
    private readonly IConfiguration _configuration;
    private readonly ILoginTokenStore _loginTokenStore;
    private readonly IPkceStateManager _stateManager;
    private readonly IBrandingProvider _brandingProvider;

    public LoginController(
        ILogger<LoginController> logger,
        IConfiguration configuration,
        ILoginTokenStore loginTokenStore,
        IPkceStateManager stateManager,
        IBrandingProvider brandingProvider)
    {
        _logger = logger;
        _configuration = configuration;
        _loginTokenStore = loginTokenStore;
        _stateManager = stateManager;
        _brandingProvider = brandingProvider;
    }

    /// <summary>
    /// Display the custom login page
    /// </summary>
    [HttpGet("")]
    public async Task<IActionResult> Index([FromQuery] string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            _logger.LogWarning("Login page accessed without token");
            return View("Index", CreateLoginModel(
                loginToken: "",
                errorMessage: "Ongeldige login aanvraag. Token ontbreekt.",
                isExpired: true
            ));
        }

        // Validate the login token
        var loginData = await _loginTokenStore.GetLoginTokenData(token);
        if (loginData == null || loginData.IsUsed)
        {
            _logger.LogWarning("Invalid or expired login token: {Token}", token);
            return View("Index", CreateLoginModel(
                loginToken: token,
                errorMessage: "Deze login link is verlopen of ongeldig.",
                isExpired: true
            ));
        }

        // Check if expired
        if (loginData.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Login token expired: {Token}", token);
            return View("Index", CreateLoginModel(
                loginToken: token,
                errorMessage: "Deze login link is verlopen. Probeer het opnieuw.",
                isExpired: true
            ));
        }

        var model = CreateLoginModel(
            loginToken: token,
            isExpired: false
        );

        return View("Index", model);
    }

    /// <summary>
    /// Helper method to create a LoginPageModel with branding configuration
    /// </summary>
    private LoginPageModel CreateLoginModel(string loginToken, string? errorMessage = null, bool isExpired = false)
    {
        var branding = _brandingProvider.Get();

        return new LoginPageModel
        {
            LoginToken = loginToken,
            ErrorMessage = errorMessage,
            IsExpired = isExpired,
            CompanyName = branding.CompanyName,
            ProductName = branding.ProductName,
            PrimaryColor = branding.PrimaryColor,
            PrimaryHoverColor = branding.PrimaryHoverColor
        };
    }

    /// <summary>
    /// User confirmed - redirect to Entra ID
    /// </summary>
    [HttpPost("Continue")]
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
            var redirectUri = $"{Request.Scheme}://{Request.Host}/oauth/callback";

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
    [HttpPost("Cancel")]
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
}
