using Microsoft.Extensions.Configuration;

namespace MCP.Services;

public interface IBrandingProvider
{
    (string CompanyName, string ProductName, string PrimaryColor, string PrimaryHoverColor) Get();
}

public class BrandingProvider : IBrandingProvider
{
    private readonly IConfiguration _configuration;

    public BrandingProvider(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    private string GetValue(string key, string @default)
    {
        // Supports both appsettings.json (Branding:Key) and Azure App Settings (Branding__Key)
        var value = _configuration[$"Branding:{key}"];
        if (string.IsNullOrWhiteSpace(value))
            value = _configuration[$"Branding__{key}"];
        return string.IsNullOrWhiteSpace(value) ? @default : value!;
    }

    public (string CompanyName, string ProductName, string PrimaryColor, string PrimaryHoverColor) Get()
    {
        var companyName = GetValue("CompanyName", "Your Company");
        var productName = GetValue("ProductName", "MCP Server");
        var primaryColor = GetValue("PrimaryColor", "#0066cc");
        var primaryHoverColor = GetValue("PrimaryHoverColor", "#0052a3");
        return (companyName, productName, primaryColor, primaryHoverColor);
    }
}
