# Phase 4: Create XAF Blazor Server Client
# Based on working example patterns, specifically configured for XAF Blazor Server

Write-Host "=== PHASE 4: CONFIGURING XAF BLAZOR CLIENT ===" -ForegroundColor Cyan
Write-Host "Creating xaf-blazor-server client with working configuration..." -ForegroundColor Yellow

# Get admin token
$response = Invoke-RestMethod -Uri "http://localhost:8080/realms/master/protocol/openid-connect/token" -Method Post -Body @{
    grant_type = "password"
    client_id = "admin-cli"
    username = "Admin"
    password = "JoseManuel16"
} -ContentType "application/x-www-form-urlencoded"

$token = $response.access_token
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# Define XAF-specific URLs (our actual runtime URLs)
$baseUrls = @("https://localhost:5001", "http://localhost:5000")
$redirectUris = @()
$postLogoutRedirectUris = @()

foreach ($baseUrl in $baseUrls) {
    $redirectUris += @(
        "$baseUrl/",
        "$baseUrl/signin-oidc",
        "$baseUrl/authentication/login-callback"
    )
    $postLogoutRedirectUris += @(
        "$baseUrl/",
        "$baseUrl/authentication/logout-callback",
        "$baseUrl/signout-callback-oidc"
    )
}

Write-Host "Creating XAF Blazor Server client..." -ForegroundColor Yellow

# Create client with exact working example configuration
$client = @{
    clientId = "xaf-blazor-server"
    name = "XAF Blazor Server Application"
    description = "OpenID Connect client for XAF Blazor Server"
    enabled = $true
    clientAuthenticatorType = "client-secret"
    secret = "xaf-blazor-server-secret-2024"
    redirectUris = $redirectUris
    webOrigins = $baseUrls
    protocol = "openid-connect"
    publicClient = $false
    frontchannelLogout = $true
    attributes = @{
        "pkce.code.challenge.method" = "S256"
        "post.logout.redirect.uris" = ($postLogoutRedirectUris -join "##")
    }
    standardFlowEnabled = $true
    implicitFlowEnabled = $false
    directAccessGrantsEnabled = $false
    serviceAccountsEnabled = $false
    fullScopeAllowed = $true
}

try {
    $jsonBody = $client | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth/clients" -Method Post -Body $jsonBody -Headers $headers
    Write-Host "XAF Blazor Server client created successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create client: $($_.Exception.Message)"
    exit 1
}

Write-Host ""
Write-Host "=== XAF BLAZOR CLIENT CONFIGURATION ===" -ForegroundColor Green
Write-Host "Client ID: xaf-blazor-server" -ForegroundColor White
Write-Host "Client Secret: xaf-blazor-server-secret-2024" -ForegroundColor White
Write-Host ""
Write-Host "Configuration Settings (matching working example):" -ForegroundColor Green
Write-Host "  Authentication Type: client-secret" -ForegroundColor Gray
Write-Host "  Public Client: false" -ForegroundColor Gray
Write-Host "  Standard Flow: true" -ForegroundColor Gray
Write-Host "  Implicit Flow: false" -ForegroundColor Gray
Write-Host "  Direct Access Grants: false" -ForegroundColor Gray
Write-Host "  Service Accounts: false" -ForegroundColor Gray
Write-Host "  Full Scope Allowed: true" -ForegroundColor Gray
Write-Host "  Front Channel Logout: true" -ForegroundColor Gray
Write-Host "  PKCE: S256 challenge method" -ForegroundColor Gray
Write-Host ""
Write-Host "Redirect URIs:" -ForegroundColor Green
foreach ($uri in $redirectUris) {
    Write-Host "  $uri" -ForegroundColor Gray
}
Write-Host ""
Write-Host "Web Origins:" -ForegroundColor Green
foreach ($origin in $baseUrls) {
    Write-Host "  $origin" -ForegroundColor Gray
}
Write-Host ""
Write-Host "Phase 4 Complete - XAF client configured with working patterns!" -ForegroundColor Green