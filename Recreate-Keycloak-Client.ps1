# Comprehensive Keycloak Client Fix Script
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
    
    Write-Host "Current client configuration:" -ForegroundColor Green
    Write-Host "  Client ID: $($client.clientId)" -ForegroundColor White
    Write-Host "  Client UUID: $($client.id)" -ForegroundColor Gray
    Write-Host "  Public Client: $($client.publicClient)" -ForegroundColor White
    Write-Host "  Client Authenticator: $($client.clientAuthenticatorType)" -ForegroundColor White
    Write-Host "  Standard Flow: $($client.standardFlowEnabled)" -ForegroundColor White
    Write-Host "  Direct Access Grants: $($client.directAccessGrantsEnabled)" -ForegroundColor White
    Write-Host "  PKCE Required: $($client.attributes.'pkce.code.challenge.method')" -ForegroundColor White
    
    # Delete the existing client and recreate it with proper configuration
    Write-Host "`nDeleting existing client to recreate with proper settings..." -ForegroundColor Yellow
    Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($client.id)" -Headers $headers -Method Delete
    Write-Host "Existing client deleted successfully" -ForegroundColor Green
    
    # Create new client with proper configuration
    Write-Host "Creating new client with correct configuration..." -ForegroundColor Yellow
    
    $newClientConfig = @{
        clientId = $ClientId
        name = "XAF Keycloak Auth Blazor Application"
        description = "XAF Blazor Server application with Keycloak authentication - Recreated"
        enabled = $true
        protocol = "openid-connect"
        
        # Client type settings
        publicClient = $false
        bearerOnly = $false
        
        # Flow settings
        standardFlowEnabled = $true
        implicitFlowEnabled = $false
        directAccessGrantsEnabled = $true
        serviceAccountsEnabled = $false
        
        # Authentication settings
        clientAuthenticatorType = "client-secret"
        
        # PKCE settings - disable for confidential clients with client secret
        attributes = @{
            "pkce.code.challenge.method" = ""
            "exclude.session.state.from.auth.response" = "false"
            "oauth2.device.authorization.grant.enabled" = "false"
            "oidc.ciba.grant.enabled" = "false"
            "backchannel.logout.session.required" = "true"
            "backchannel.logout.revoke.offline.tokens" = "false"
        }
        
        # URLs
        rootUrl = "https://localhost:5001"
        adminUrl = "https://localhost:5001"
        baseUrl = "https://localhost:5001"
        
        # Redirect URIs
        redirectUris = @(
            "https://localhost:5001/signin-keycloak",
            "https://localhost:44318/signin-keycloak",
            "http://localhost:5000/signin-keycloak",
            "http://localhost:65201/signin-keycloak"
        )
        
        # Web origins
        webOrigins = @(
            "https://localhost:5001",
            "https://localhost:44318",
            "http://localhost:5000",
            "http://localhost:65201"
        )
        
        # Default scopes
        defaultClientScopes = @("web-origins", "role_list", "profile", "roles", "email")
        optionalClientScopes = @("address", "phone", "offline_access", "microprofile-jwt")
        
        # Other settings
        fullScopeAllowed = $true
        nodeReRegistrationTimeout = -1
        notBefore = 0
        surrogateAuthRequired = $false
        authorizationServicesEnabled = $false
    }
    
    $clientBody = $newClientConfig | ConvertTo-Json -Depth 10
    
    # Create the client
    $createResponse = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Headers $headers -Method Post -Body $clientBody
    
    Write-Host "New client created successfully!" -ForegroundColor Green
    
    # Get the new client ID
    $newClients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers $headers -Method Get
    $newClient = $newClients[0]
    
    # Get the client secret
    Write-Host "Getting client secret..." -ForegroundColor Yellow
    $secretResponse = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($newClient.id)/client-secret" -Headers $headers -Method Get
    $clientSecret = $secretResponse.value
    
    if (-not $clientSecret) {
        # Generate new secret if none exists
        Write-Host "Generating new client secret..." -ForegroundColor Yellow
        $newSecretResponse = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($newClient.id)/client-secret" -Headers $headers -Method Post
        $clientSecret = $newSecretResponse.value
    }
    
    # Display the configuration
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "NEW CLIENT CONFIGURATION" -ForegroundColor Cyan
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
                "UsePkce" = $false
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Host $configJson -ForegroundColor White
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "IMPORTANT CHANGES:" -ForegroundColor Yellow
    Write-Host "1. Client recreated with proper confidential client settings" -ForegroundColor White
    Write-Host "2. PKCE disabled for confidential client (UsePkce = false)" -ForegroundColor White
    Write-Host "3. Client secret authentication enabled" -ForegroundColor White
    Write-Host "4. All redirect URIs updated" -ForegroundColor White
    Write-Host "`nNEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Update appsettings.json with new ClientSecret: $clientSecret" -ForegroundColor White
    Write-Host "2. Set UsePkce to false in appsettings.json" -ForegroundColor White
    Write-Host "3. Restart your application" -ForegroundColor White
    Write-Host "4. Test authentication" -ForegroundColor White
    Write-Host "="*80 -ForegroundColor Cyan
    
    # Save configuration
    $configJson | Out-File -FilePath "keycloak-new-config.json" -Encoding UTF8
    Write-Host "`nConfiguration saved to keycloak-new-config.json" -ForegroundColor Gray
    
    # Return the new client secret for easy copying
    Write-Host "`nNew Client Secret: $clientSecret" -ForegroundColor Green
}
catch {
    Write-Error "Failed to fix client configuration: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Error "Response: $responseBody"
    }
    exit 1
}