# Recreate Keycloak Client with Working Example Configuration
# This script recreates the client with the exact same settings as the working Blazor example

param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUsername = "Admin",
    [string]$AdminPassword = "JoseManuel16", 
    [string]$RealmName = "XafKeycloakAuth",
    [string]$ClientId = "xaf-keycloak-auth-blazor",
    [string]$ClientSecret = "your-blazor-client-secret-here"
)

Write-Host "=== RECREATING CLIENT WITH WORKING EXAMPLE CONFIGURATION ===" -ForegroundColor Cyan
Write-Host "Problem: Client configuration doesn't match working example" -ForegroundColor Yellow
Write-Host "Solution: Recreate client with exact same settings as working Blazor app" -ForegroundColor Green
Write-Host ""

# Get admin access token
Write-Host "Getting admin access token..." -ForegroundColor Yellow
$tokenUrl = "$KeycloakUrl/realms/master/protocol/openid-connect/token"
$body = @{
    grant_type = "password"
    client_id = "admin-cli"
    username = $AdminUsername
    password = $AdminPassword
}

try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
    $token = $tokenResponse.access_token
    Write-Host "✓ Admin token obtained successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get admin token: $($_.Exception.Message)"
    exit 1
}

# Get headers for API calls
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# First, delete the existing client if it exists
Write-Host "Checking for existing client..." -ForegroundColor Yellow
try {
    $existingClients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers $headers
    if ($existingClients.Count -gt 0) {
        $existingClientUuid = $existingClients[0].id
        Write-Host "Deleting existing client..." -ForegroundColor Yellow
        Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$existingClientUuid" -Method Delete -Headers $headers
        Write-Host "✓ Existing client deleted" -ForegroundColor Green
    }
}
catch {
    Write-Host "No existing client found or error checking: $($_.Exception.Message)" -ForegroundColor Gray
}

# Define redirect URIs (matching working example)
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

# Create client with EXACT same configuration as working example
Write-Host "Creating client with working example configuration..." -ForegroundColor Yellow

$client = @{
    clientId = $ClientId
    name = "XAF Keycloak Auth Blazor Server"
    description = "OpenID Connect client for XAF Blazor Server"
    enabled = $true
    clientAuthenticatorType = "client-secret"
    secret = $ClientSecret
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
    $response = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Method Post -Body $jsonBody -Headers $headers
    Write-Host "✓ Client created successfully with working example configuration" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create client: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Host "Response: $responseBody" -ForegroundColor Red
    }
    exit 1
}

# Get the newly created client UUID
$newClients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers $headers
$newClientUuid = $newClients[0].id

Write-Host ""
Write-Host "=== CLIENT CONFIGURATION SUMMARY ===" -ForegroundColor Green
Write-Host "Client ID: $ClientId" -ForegroundColor White
Write-Host "Client UUID: $newClientUuid" -ForegroundColor White
Write-Host "Client Secret: $ClientSecret" -ForegroundColor White
Write-Host ""
Write-Host "Key Settings (matching working example):" -ForegroundColor Green
Write-Host "✓ clientAuthenticatorType: client-secret" -ForegroundColor Gray
Write-Host "✓ publicClient: false" -ForegroundColor Gray  
Write-Host "✓ standardFlowEnabled: true" -ForegroundColor Gray
Write-Host "✓ implicitFlowEnabled: false" -ForegroundColor Gray
Write-Host "✓ directAccessGrantsEnabled: false" -ForegroundColor Gray
Write-Host "✓ serviceAccountsEnabled: false" -ForegroundColor Gray
Write-Host "✓ fullScopeAllowed: true" -ForegroundColor Gray
Write-Host "✓ frontchannelLogout: true" -ForegroundColor Gray
Write-Host "✓ PKCE: S256 challenge method" -ForegroundColor Gray
Write-Host ""
Write-Host "Redirect URIs:" -ForegroundColor Green
foreach ($uri in $redirectUris) {
    Write-Host "  ✓ $uri" -ForegroundColor Gray
}
Write-Host ""
Write-Host "Web Origins:" -ForegroundColor Green
foreach ($origin in $baseUrls) {
    Write-Host "  ✓ $origin" -ForegroundColor Gray
}
Write-Host ""
Write-Host "=== NEXT STEPS ===" -ForegroundColor Cyan
Write-Host "1. Update your appsettings.json with this client secret:" -ForegroundColor White
Write-Host "   `"ClientSecret`": `"$ClientSecret`"" -ForegroundColor Yellow
Write-Host "2. Ensure UsePkce is set to true in appsettings.json" -ForegroundColor White
Write-Host "3. Test the authentication flow" -ForegroundColor White
Write-Host ""
Write-Host "✓ Client recreated with working example configuration!" -ForegroundColor Green