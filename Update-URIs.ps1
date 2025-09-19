Write-Host "Fixing Redirect URIs..." -ForegroundColor Cyan

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

# Get client
$clients = Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth/clients?clientId=xaf-keycloak-auth-blazor" -Headers $headers
$client = $clients[0]
$clientUuid = $client.id

Write-Host "Current redirect URIs:"
$client.redirectUris | ForEach-Object { Write-Host "  $_" }

# Update with correct URIs
$update = @{
    clientId = "xaf-keycloak-auth-blazor"
    redirectUris = @(
        "https://localhost:5001/"
        "https://localhost:5001/signin-oidc"
        "http://localhost:5000/"
        "http://localhost:5000/signin-oidc"
    )
    webOrigins = @("https://localhost:5001", "http://localhost:5000")
    standardFlowEnabled = $true
    publicClient = $false
}

$json = $update | ConvertTo-Json -Depth 10
Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth/clients/$clientUuid" -Method Put -Body $json -Headers $headers

Write-Host "Updated redirect URIs:" -ForegroundColor Green
$update.redirectUris | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }