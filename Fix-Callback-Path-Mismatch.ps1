# Fix Callback Path Mismatch - Update Keycloak client with standard Microsoft callback URIs
# This script updates the existing client to use the standard Microsoft authentication callback paths
# that the working Blazor Server example uses

param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUsername = "Admin",
    [string]$AdminPassword = "JoseManuel16",
    [string]$RealmName = "XafKeycloakAuth",
    [string]$ClientId = "xaf-keycloak-auth-blazor",
    [string]$BaseUrl = "https://localhost:44318"
)

Write-Host "=== FIXING CALLBACK PATH MISMATCH ===" -ForegroundColor Cyan
Write-Host "Problem: XAF app is using '/signin-keycloak' but should use '/signin-oidc'" -ForegroundColor Yellow
Write-Host "Solution: Update Keycloak client with standard Microsoft callback URIs" -ForegroundColor Green
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

# Get client details
Write-Host "Getting client details..." -ForegroundColor Yellow
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
    Write-Host "✓ Client found: $($client.clientId) (UUID: $clientUuid)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get client details: $($_.Exception.Message)"
    exit 1
}

# Define the correct redirect URIs (matching the working Blazor example)
$redirectUris = @(
    "$BaseUrl/",
    "$BaseUrl/signin-oidc",  # Standard Microsoft callback path
    "$BaseUrl/authentication/login-callback"
)

$postLogoutRedirectUris = @(
    "$BaseUrl/",
    "$BaseUrl/signout-callback-oidc",  # Standard Microsoft signout path
    "$BaseUrl/authentication/logout-callback"
)

# Update client configuration
Write-Host "Updating client with standard Microsoft callback URIs..." -ForegroundColor Yellow

$clientUpdate = @{
    clientId = $ClientId
    redirectUris = $redirectUris
    webOrigins = @($BaseUrl)
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
    Write-Host "✓ Client updated successfully with standard callback URIs" -ForegroundColor Green
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
Write-Host "Verifying client configuration..." -ForegroundColor Yellow
try {
    $updatedClient = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$clientUuid" -Headers $headers
    
    Write-Host ""
    Write-Host "=== UPDATED CLIENT CONFIGURATION ===" -ForegroundColor Green
    Write-Host "Client ID: $($updatedClient.clientId)" -ForegroundColor White
    Write-Host "Redirect URIs:" -ForegroundColor White
    foreach ($uri in $updatedClient.redirectUris) {
        Write-Host "  • $uri" -ForegroundColor Gray
    }
    Write-Host "Web Origins:" -ForegroundColor White
    foreach ($origin in $updatedClient.webOrigins) {
        Write-Host "  • $origin" -ForegroundColor Gray
    }
    Write-Host "PKCE Support: $($updatedClient.attributes.'pkce.code.challenge.method')" -ForegroundColor White
    Write-Host "Public Client: $($updatedClient.publicClient)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "=== NEXT STEPS ===" -ForegroundColor Cyan
    Write-Host "1. The client now uses standard Microsoft callback paths:" -ForegroundColor White
    Write-Host "   • /signin-oidc (instead of /signin-keycloak)" -ForegroundColor Gray
    Write-Host "   • /signout-callback-oidc (instead of /signout-callback-keycloak)" -ForegroundColor Gray
    Write-Host "2. PKCE is properly configured with S256 challenge method" -ForegroundColor White
    Write-Host "3. Your appsettings.json has been updated to use these paths" -ForegroundColor White
    Write-Host "4. Run the application and test the authentication flow" -ForegroundColor White
    Write-Host ""
    Write-Host "✓ Callback path mismatch should now be resolved!" -ForegroundColor Green
}
catch {
    Write-Warning "Could not verify client configuration, but update completed"
}

Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Problem Identified: Callback path mismatch" -ForegroundColor Yellow
Write-Host "• XAF app was using: /signin-keycloak" -ForegroundColor Red
Write-Host "• Working example uses: /signin-oidc" -ForegroundColor Green
Write-Host "• This mismatch causes 'unauthorized_client' errors" -ForegroundColor Red
Write-Host ""
Write-Host "Solution Applied:" -ForegroundColor Green
Write-Host "• Updated appsettings.json to use /signin-oidc" -ForegroundColor White
Write-Host "• Updated Keycloak client redirect URIs" -ForegroundColor White
Write-Host "• Enabled PKCE with S256 challenge method" -ForegroundColor White
Write-Host ""
Write-Host "This should resolve the persistent unauthorized_client error!" -ForegroundColor Green