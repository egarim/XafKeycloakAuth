Write-Host "Recreating Keycloak client with working configuration..." -ForegroundColor Cyan

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

# Delete existing client
try {
    $existingClients = Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth/clients?clientId=xaf-keycloak-auth-blazor" -Headers $headers
    if ($existingClients.Count -gt 0) {
        $clientUuid = $existingClients[0].id
        Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth/clients/$clientUuid" -Method Delete -Headers $headers
        Write-Host "Deleted existing client" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "No existing client found"
}

# Create new client with working configuration
$client = @{
    clientId = "xaf-keycloak-auth-blazor"
    name = "XAF Keycloak Auth Blazor Server"
    enabled = $true
    clientAuthenticatorType = "client-secret"
    secret = "your-blazor-client-secret-here"
    redirectUris = @(
        "https://localhost:5001/"
        "https://localhost:5001/signin-oidc"
        "https://localhost:5001/authentication/login-callback"
        "http://localhost:5000/"
        "http://localhost:5000/signin-oidc"
        "http://localhost:5000/authentication/login-callback"
    )
    webOrigins = @("https://localhost:5001", "http://localhost:5000")
    protocol = "openid-connect"
    publicClient = $false
    frontchannelLogout = $true
    attributes = @{
        "pkce.code.challenge.method" = "S256"
    }
    standardFlowEnabled = $true
    implicitFlowEnabled = $false
    directAccessGrantsEnabled = $false
    serviceAccountsEnabled = $false
    fullScopeAllowed = $true
}

$json = $client | ConvertTo-Json -Depth 10
Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth/clients" -Method Post -Body $json -Headers $headers

Write-Host "Client recreated with working configuration:" -ForegroundColor Green
Write-Host "  Client ID: xaf-keycloak-auth-blazor" -ForegroundColor Gray
Write-Host "  Client Secret: your-blazor-client-secret-here" -ForegroundColor Gray
Write-Host "  PKCE: Enabled with S256" -ForegroundColor Gray
Write-Host "  Public Client: false" -ForegroundColor Gray
Write-Host "  Standard Flow: true" -ForegroundColor Gray
Write-Host "  Direct Access Grants: false" -ForegroundColor Gray
Write-Host "Client configuration now matches working example!" -ForegroundColor Green