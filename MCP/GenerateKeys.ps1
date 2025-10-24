# Generate Random Keys for MCP OAuth Proxy
# Run this script to generate secure JWT signing and encryption keys

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "MCP - Key Generator" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Generate JWT Signing Key (64 bytes = 512 bits)
Write-Host "Generating JWT Signing Key..." -ForegroundColor Yellow
$signingBytes = New-Object byte[] 64
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($signingBytes)
$signingKey = [Convert]::ToBase64String($signingBytes)

# Generate Encryption Key (64 bytes = 512 bits)
Write-Host "Generating Encryption Key..." -ForegroundColor Yellow
$encryptionBytes = New-Object byte[] 64
$rng.GetBytes($encryptionBytes)
$encryptionKey = [Convert]::ToBase64String($encryptionBytes)
$rng.Dispose()

Write-Host ""
Write-Host "✅ Keys generated successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Copy these values to your configuration:" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "For appsettings.json:" -ForegroundColor White
Write-Host ""
Write-Host '"Jwt": {' -ForegroundColor Gray
Write-Host "  `"SigningKey`": `"$signingKey`"," -ForegroundColor Green
Write-Host "  `"EncryptionKey`": `"$encryptionKey`"," -ForegroundColor Green
Write-Host '  "ExpirationMinutes": "60"' -ForegroundColor Gray
Write-Host "}" -ForegroundColor Gray
Write-Host ""

Write-Host "For Azure App Service Configuration:" -ForegroundColor White
Write-Host ""
Write-Host "Jwt__SigningKey = $signingKey" -ForegroundColor Green
Write-Host "Jwt__EncryptionKey = $encryptionKey" -ForegroundColor Green
Write-Host ""

Write-Host "⚠️  SECURITY WARNING:" -ForegroundColor Red
Write-Host "Store these keys securely!" -ForegroundColor Yellow
Write-Host "In production, use Azure Key Vault instead of app settings." -ForegroundColor Yellow
Write-Host ""

# Optionally save to file
$saveToFile = Read-Host "Save keys to file? (y/n)"
if ($saveToFile -eq "y" -or $saveToFile -eq "Y") {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "generated_keys_$timestamp.txt"
    
    $content = @"
MCP - Generated Keys
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

JWT Signing Key:
$signingKey

Encryption Key:
$encryptionKey

⚠️ WARNING: Keep these keys secure and never commit them to source control!
"@
    
    $content | Out-File -FilePath $filename -Encoding UTF8
    Write-Host "Keys saved to: $filename" -ForegroundColor Green
    Write-Host ""
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
