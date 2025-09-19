# Fix Redirect URI - Update with correct URLs
param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUsername = "Admin", 
    [string]$AdminPassword = "JoseManuel16",
    [string]$RealmName = "XafKeycloakAuth",
    [string]$ClientId = "xaf-keycloak-auth-blazor"
)

Write-Host "=== FIXING REDIRECT URI MISMATCH ===" -ForegroundColor Cyan

# Get admin access token
$tokenUrl = "$KeycloakUrl/realms/master/protocol/openid-connect/token"
$body = @{
    grant_type = "password"
    client_id = "admin-cli"
    username = $AdminUsername
    password = $AdminPassword
}

$tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
$token = $tokenResponse.access_token

# Get current client configuration
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$clientsResponse = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers $headers
$client = $clientsResponse[0]
$clientUuid = $client.id

Write-Host "Current Redirect URIs:" -ForegroundColor Red
foreach ($uri in $client.redirectUris) {
    Write-Host "  • $uri" -ForegroundColor Gray
}

# Define correct redirect URIs
$redirectUris = @(
    "https://localhost:5001/",
    "https://localhost:5001/signin-oidc",
    "http://localhost:5000/",
    "http://localhost:5000/signin-oidc"
)

$webOrigins = @(
    "https://localhost:5001",
    "http://localhost:5000"
)

# Update client configuration
$clientUpdate = @{
    clientId = $ClientId
    redirectUris = $redirectUris
    webOrigins = $webOrigins
    standardFlowEnabled = $true
    publicClient = $false
}

$jsonBody = $clientUpdate | ConvertTo-Json -Depth 10
Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$clientUuid" -Method Put -Body $jsonBody -Headers $headers

Write-Host "✓ Client updated with correct URLs:" -ForegroundColor Green
foreach ($uri in $redirectUris) {
    Write-Host "  ✓ $uri" -ForegroundColor Gray
}