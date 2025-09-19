# Script to regenerate Keycloak client secret and update configuration
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

try {
    $headers = @{
        Authorization = "Bearer $adminToken"
        "Content-Type" = "application/json"
    }
    
    # Get client information
    Write-Host "Getting client information..." -ForegroundColor Yellow
    $clients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Headers $headers -Method Get
    $client = $clients | Where-Object { $_.clientId -eq $ClientId }
    
    if (-not $client) {
        Write-Error "Client '$ClientId' not found in realm '$RealmName'"
        exit 1
    }
    
    Write-Host "Found client: $($client.clientId)" -ForegroundColor Green
    Write-Host "Client UUID: $($client.id)" -ForegroundColor Gray
    Write-Host "Public Client: $($client.publicClient)" -ForegroundColor Gray
    Write-Host "Standard Flow Enabled: $($client.standardFlowEnabled)" -ForegroundColor Gray
    Write-Host "Direct Access Grants Enabled: $($client.directAccessGrantsEnabled)" -ForegroundColor Gray
    
    # Regenerate client secret
    Write-Host "`nRegenerating client secret..." -ForegroundColor Yellow
    $newSecret = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($client.id)/client-secret" -Headers $headers -Method Post
    
    if ($newSecret -and $newSecret.value) {
        Write-Host "New client secret generated successfully!" -ForegroundColor Green
        $clientSecret = $newSecret.value
    } else {
        # Try to get existing secret
        Write-Host "Getting existing client secret..." -ForegroundColor Yellow
        $secretResponse = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($client.id)/client-secret" -Headers $headers -Method Get
        $clientSecret = $secretResponse.value
    }
    
    if (-not $clientSecret) {
        Write-Error "Failed to get client secret"
        exit 1
    }
    
    # Update client configuration to ensure proper settings
    Write-Host "`nUpdating client configuration..." -ForegroundColor Yellow
    
    $updatedClient = @{
        id = $client.id
        clientId = $client.clientId
        name = $client.name
        description = $client.description
        enabled = $true
        protocol = "openid-connect"
        publicClient = $false
        bearerOnly = $false
        standardFlowEnabled = $true
        implicitFlowEnabled = $false
        directAccessGrantsEnabled = $true
        serviceAccountsEnabled = $false
        authorizationServicesEnabled = $false
        fullScopeAllowed = $true
        clientAuthenticatorType = "client-secret"
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
        attributes = @{
            "pkce.code.challenge.method" = "S256"
            "exclude.session.state.from.auth.response" = "false"
            "saml.assertion.signature" = "false"
            "saml.force.post.binding" = "false"
            "saml.multivalued.roles" = "false"
            "saml.encrypt" = "false"
            "saml.server.signature" = "false"
            "saml.server.signature.keyinfo.ext" = "false"
            "saml_force_name_id_format" = "false"
            "saml.client.signature" = "false"
            "tls.client.certificate.bound.access.tokens" = "false"
            "saml.authnstatement" = "false"
            "display.on.consent.screen" = "false"
            "saml.onetimeuse.condition" = "false"
        }
    }
    
    $updateBody = $updatedClient | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($client.id)" -Headers $headers -Method Put -Body $updateBody
    
    Write-Host "Client configuration updated successfully!" -ForegroundColor Green
    
    # Display the updated configuration
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "UPDATED KEYCLOAK CONFIGURATION" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    $configJson = @{
        "Authentication" = @{
            "Keycloak" = @{
                "Authority" = "$KeycloakUrl/realms/$RealmName"
                "ClientId" = $ClientId
                "ClientSecret" = $clientSecret
                "RequireHttpsMetadata" = $false
                "ResponseType" = "code"
                "Scope" = "openid profile email"
                "CallbackPath" = "/signin-keycloak"
                "SignedOutCallbackPath" = "/signout-callback-keycloak"
                "GetClaimsFromUserInfoEndpoint" = $true
                "SaveTokens" = $true
                "UsePkce" = $true
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Host $configJson -ForegroundColor White
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Update the ClientSecret in your appsettings.json with: $clientSecret" -ForegroundColor White
    Write-Host "2. Restart your application" -ForegroundColor White
    Write-Host "3. Test the authentication flow" -ForegroundColor White
    Write-Host "="*80 -ForegroundColor Cyan
    
    # Save the configuration to a file for easy copying
    $configJson | Out-File -FilePath "keycloak-config.json" -Encoding UTF8
    Write-Host "`nConfiguration saved to keycloak-config.json" -ForegroundColor Gray
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