# Fix Redirect URI - Update with correct URLs
# The app is running on https://localhost:5001 but Keycloak client has wrong URLs

param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUsername = "Admin", 
    [string]$AdminPassword = "JoseManuel16",
    [string]$RealmName = "XafKeycloakAuth",
    [string]$ClientId = "xaf-keycloak-auth-blazor"
)

Write-Host "=== FIXING REDIRECT URI MISMATCH ===" -ForegroundColor Cyan
Write-Host "Problem: App runs on localhost:5001 but Keycloak has localhost:44318" -ForegroundColor Yellow
Write-Host "Solution: Update Keycloak client with correct URLs" -ForegroundColor Green
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

# Get current client configuration
Write-Host "Getting current client configuration..." -ForegroundColor Yellow
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

try {
    $clientsResponse = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers $headers
    if ($clientsResponse.Count -eq 0) {
        Write-Error "Client '$ClientId' not found in realm '$RealmName'"
        exit 1
    }
    
    $client = $clientsResponse[0]
    $clientUuid = $client.id
    
    Write-Host "=== CURRENT CLIENT CONFIGURATION ===" -ForegroundColor Red
    Write-Host "Client ID: $($client.clientId)" -ForegroundColor White
    Write-Host "Current Redirect URIs:" -ForegroundColor Red
    foreach ($uri in $client.redirectUris) {
        Write-Host "  • $uri" -ForegroundColor Gray
    }
    Write-Host ""
}
catch {
    Write-Error "Failed to get client details: $($_.Exception.Message)"
    exit 1
}

# Define correct redirect URIs for localhost:5001 and localhost:5000
$redirectUris = @(
    "https://localhost:5001/",
    "https://localhost:5001/signin-oidc",
    "https://localhost:5001/authentication/login-callback",
    "http://localhost:5000/",
    "http://localhost:5000/signin-oidc", 
    "http://localhost:5000/authentication/login-callback"
)

$postLogoutRedirectUris = @(
    "https://localhost:5001/",
    "https://localhost:5001/signout-callback-oidc",
    "https://localhost:5001/authentication/logout-callback",
    "http://localhost:5000/",
    "http://localhost:5000/signout-callback-oidc",
    "http://localhost:5000/authentication/logout-callback"
)

$webOrigins = @(
    "https://localhost:5001",
    "http://localhost:5000"
)

# Update client configuration
Write-Host "Updating client with correct URLs..." -ForegroundColor Yellow

$clientUpdate = @{
    clientId = $ClientId
    redirectUris = $redirectUris
    webOrigins = $webOrigins
    attributes = @{
        "pkce.code.challenge.method" = "S256"
        "post.logout.redirect.uris" = ($postLogoutRedirectUris -join "##")
    }
    standardFlowEnabled = $true
    publicClient = $false
    frontchannelLogout = $true
}

try {
    $jsonBody = $clientUpdate | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$clientUuid" -Method Put -Body $jsonBody -Headers $headers
    Write-Host "✓ Client updated successfully with correct URLs" -ForegroundColor Green
}
catch {
    Write-Error "Failed to update client: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Host "Response: $responseBody" -ForegroundColor Red
    }
    exit 1
}

# Verify the changes
Write-Host "Verifying updated configuration..." -ForegroundColor Yellow
try {
    $updatedClient = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$clientUuid" -Headers $headers
    
    Write-Host ""
    Write-Host "=== UPDATED CLIENT CONFIGURATION ===" -ForegroundColor Green
    Write-Host "Client ID: $($updatedClient.clientId)" -ForegroundColor White
    Write-Host "Redirect URIs:" -ForegroundColor Green
    foreach ($uri in $updatedClient.redirectUris) {
        Write-Host "  ✓ $uri" -ForegroundColor Gray
    }
    Write-Host "Web Origins:" -ForegroundColor Green
    foreach ($origin in $updatedClient.webOrigins) {
        Write-Host "  ✓ $origin" -ForegroundColor Gray
    }
    Write-Host ""
    
    Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
    Write-Host "✓ Fixed URL mismatch:" -ForegroundColor Green
    Write-Host "  • App runs on: https://localhost:5001 and http://localhost:5000" -ForegroundColor White
    Write-Host "  • Keycloak client now has correct redirect URIs" -ForegroundColor White
    Write-Host "  • Standard Microsoft callback paths: /signin-oidc" -ForegroundColor White
    Write-Host "  • PKCE enabled with S256 challenge method" -ForegroundColor White
    Write-Host ""
    Write-Host "The 'Invalid parameter: redirect_uri' error should now be resolved!" -ForegroundColor Green
}
catch {
    Write-Warning "Could not verify client configuration, but update completed"
}