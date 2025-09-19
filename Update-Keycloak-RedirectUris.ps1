# Script to update Keycloak client redirect URIs
param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUser = "Admin",
    [string]$AdminPassword = "JoseManuel16",
    [string]$RealmName = "XafKeycloakAuth",
    [string]$ClientId = "xaf-keycloak-auth-blazor"
)

# Function to get admin access token
function Get-AdminAccessToken {
    param($KeycloakUrl, $AdminUser, $AdminPassword)
    
    $body = @{
        grant_type = "password"
        client_id = "admin-cli"
        username = $AdminUser
        password = $AdminPassword
    }
    
    try {
        $response = Invoke-RestMethod -Uri "$KeycloakUrl/realms/master/protocol/openid-connect/token" -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-Error "Failed to get admin token: $($_.Exception.Message)"
        return $null
    }
}

# Get admin token
Write-Host "Getting admin access token..." -ForegroundColor Yellow
$adminToken = Get-AdminAccessToken -KeycloakUrl $KeycloakUrl -AdminUser $AdminUser -AdminPassword $AdminPassword

if (-not $adminToken) {
    Write-Error "Failed to get admin token. Exiting."
    exit 1
}

# Get existing client configuration
Write-Host "Getting current client configuration..." -ForegroundColor Yellow
try {
    $headers = @{
        Authorization = "Bearer $adminToken"
        "Content-Type" = "application/json"
    }
    
    $clients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Headers $headers -Method Get
    $client = $clients | Where-Object { $_.clientId -eq $ClientId }
    
    if (-not $client) {
        Write-Error "Client '$ClientId' not found in realm '$RealmName'"
        exit 1
    }
    
    Write-Host "Current client configuration:" -ForegroundColor Green
    Write-Host "Client ID: $($client.clientId)" -ForegroundColor White
    Write-Host "Current Redirect URIs: $($client.redirectUris -join ', ')" -ForegroundColor White
    Write-Host "Current Web Origins: $($client.webOrigins -join ', ')" -ForegroundColor White
    
    # Update the client with correct redirect URIs
    $updatedClient = @{
        id = $client.id
        clientId = $client.clientId
        redirectUris = @(
            "https://localhost:5001/signin-keycloak",
            "https://localhost:44318/signin-keycloak",
            "http://localhost:5000/signin-keycloak",
            "http://localhost:65201/signin-keycloak"
        )
        webOrigins = @(
            "https://localhost:5001",
            "https://localhost:44318", 
            "http://localhost:5000",
            "http://localhost:65201"
        )
        clientAuthenticatorType = $client.clientAuthenticatorType
        secret = $client.secret
        publicClient = $client.publicClient
        protocol = $client.protocol
        enabled = $client.enabled
        serviceAccountsEnabled = $client.serviceAccountsEnabled
        directAccessGrantsEnabled = $client.directAccessGrantsEnabled
        standardFlowEnabled = $client.standardFlowEnabled
        implicitFlowEnabled = $client.implicitFlowEnabled
    }
    
    $updateBody = $updatedClient | ConvertTo-Json -Depth 10
    
    Write-Host "Updating client redirect URIs..." -ForegroundColor Yellow
    Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($client.id)" -Headers $headers -Method Put -Body $updateBody
    
    Write-Host "Successfully updated client redirect URIs!" -ForegroundColor Green
    Write-Host "New Redirect URIs:" -ForegroundColor White
    $updatedClient.redirectUris | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
    Write-Host "New Web Origins:" -ForegroundColor White
    $updatedClient.webOrigins | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
}
catch {
    Write-Error "Failed to update client configuration: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Error "Response: $responseBody"
    }
    exit 1
}

Write-Host "`nClient configuration updated successfully!" -ForegroundColor Green
Write-Host "You can now test the authentication with any of these URLs:" -ForegroundColor Yellow
Write-Host "  - https://localhost:5001" -ForegroundColor Gray
Write-Host "  - https://localhost:44318" -ForegroundColor Gray
Write-Host "  - http://localhost:5000" -ForegroundColor Gray
Write-Host "  - http://localhost:65201" -ForegroundColor Gray