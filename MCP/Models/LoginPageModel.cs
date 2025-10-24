namespace MCP.Models;

/// <summary>
/// View model for the custom login page.
/// </summary>
public class LoginPageModel
{
    /// <summary>
    /// The login token used to continue the OAuth flow
    /// </summary>
    public required string LoginToken { get; set; }

    /// <summary>
    /// Error message to display (if any)
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Whether the token has expired
    /// </summary>
    public bool IsExpired { get; set; } = false;

    /// <summary>
    /// Company name for branding
    /// </summary>
    public string CompanyName { get; set; } = "Your Company";

    /// <summary>
    /// Product name for branding
    /// </summary>
    public string ProductName { get; set; } = "MCP Server";

    /// <summary>
    /// Primary color for branding (hex format)
    /// </summary>
    public string PrimaryColor { get; set; } = "#0066cc";

    /// <summary>
    /// Primary hover color for branding (hex format)
    /// </summary>
    public string PrimaryHoverColor { get; set; } = "#0052a3";
}
