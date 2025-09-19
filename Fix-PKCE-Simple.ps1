# PKCE Confidential Client Conflict Fix
param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUser = "Admin",
    [string]$AdminPassword = "JoseManuel16",
    [string]$RealmName = "XafKeycloakAuth",
    [string]$ClientId = "xaf-keycloak-auth-blazor"
)

Write-Host "PKCE + Confidential Client Conflict Fix" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Gray

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

Write-Host "Getting admin access token..." -ForegroundColor Yellow
$adminToken = Get-AdminAccessToken -KeycloakUrl $KeycloakUrl -AdminUser $AdminUser -AdminPassword $AdminPassword

if (-not $adminToken) {
    Write-Error "Authentication failed. Cannot proceed."
    exit 1
}

try {
    $headers = @{
        Authorization = "Bearer $adminToken"
        "Content-Type" = "application/json"
    }
    
    Write-Host "Analyzing current client configuration..." -ForegroundColor Yellow
    $clients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Headers $headers -Method Get
    $client = $clients | Where-Object { $_.clientId -eq $ClientId }
    
    if (-not $client) {
        Write-Error "Client '$ClientId' not found in realm '$RealmName'"
        exit 1
    }
    
    Write-Host "CONFLICT ANALYSIS:" -ForegroundColor Red
    Write-Host "Client ID: $($client.clientId)" -ForegroundColor White
    Write-Host "Client Type: $(if ($client.publicClient) { 'Public' } else { 'Confidential' })" -ForegroundColor White
    Write-Host "Client Authenticator: $($client.clientAuthenticatorType)" -ForegroundColor White
    
    $pkceMethod = $client.attributes.'pkce.code.challenge.method'
    if ($pkceMethod) {
        Write-Host "PKCE Method: $pkceMethod" -ForegroundColor Red
        Write-Host "PROBLEM DETECTED: PKCE is ENABLED on a CONFIDENTIAL client!" -ForegroundColor Red
    } else {
        Write-Host "PKCE Method: Not set (disabled)" -ForegroundColor Green
    }
    
    Write-Host "APPLYING FIX..." -ForegroundColor Yellow
    
    # Create fixed attributes
    $fixedAttributes = @{}
    if ($client.attributes) {
        foreach ($attr in $client.attributes.PSObject.Properties) {
            if ($attr.Name -ne "pkce.code.challenge.method") {
                $fixedAttributes[$attr.Name] = $attr.Value
            }
        }
    }
    
    # Explicitly disable PKCE
    $fixedAttributes["pkce.code.challenge.method"] = ""
    
    # Create update payload
    $updatePayload = @{
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
        clientAuthenticatorType = "client-secret"
        attributes = $fixedAttributes
        redirectUris = $client.redirectUris
        webOrigins = $client.webOrigins
        rootUrl = $client.rootUrl
        baseUrl = $client.baseUrl
        adminUrl = $client.adminUrl
        defaultClientScopes = $client.defaultClientScopes
        optionalClientScopes = $client.optionalClientScopes
        fullScopeAllowed = $client.fullScopeAllowed
        nodeReRegistrationTimeout = $client.nodeReRegistrationTimeout
        notBefore = $client.notBefore
        surrogateAuthRequired = $false
        authorizationServicesEnabled = $false
    }
    
    $updateBody = $updatePayload | ConvertTo-Json -Depth 10
    
    # Update the client
    Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($client.id)" -Headers $headers -Method Put -Body $updateBody
    
    # Get client secret
    $secretResponse = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($client.id)/client-secret" -Headers $headers -Method Get
    $clientSecret = $secretResponse.value
    
    Write-Host "Client configuration fixed successfully!" -ForegroundColor Green
    
    # Verification
    Write-Host "VERIFICATION:" -ForegroundColor Green
    $updatedClients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers $headers -Method Get
    $updatedClient = $updatedClients[0]
    $updatedPkce = $updatedClient.attributes.'pkce.code.challenge.method'
    
    Write-Host "Client Type: $(if ($updatedClient.publicClient) { 'Public' } else { 'Confidential (CORRECT)' })" -ForegroundColor White
    Write-Host "Client Auth: $($updatedClient.clientAuthenticatorType) (CORRECT)" -ForegroundColor White
    Write-Host "PKCE Status: $(if ([string]::IsNullOrEmpty($updatedPkce)) { 'Disabled (CORRECT)' } else { 'Enabled (ERROR)' })" -ForegroundColor White
    
    # Display configuration
    Write-Host "BLAZOR SERVER CONFIGURATION:" -ForegroundColor Cyan
    Write-Host "Use this configuration in your appsettings.json:" -ForegroundColor Yellow
    
    $blazorConfig = @{
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
    
    Write-Host $blazorConfig -ForegroundColor White
    
    Write-Host "CRITICAL POINTS FOR BLAZOR SERVER:" -ForegroundColor Red
    Write-Host "1. ClientSecret must be present (confidential client)" -ForegroundColor White
    Write-Host "2. UsePkce MUST be false" -ForegroundColor White
    Write-Host "3. Never use PKCE with confidential clients" -ForegroundColor White
    Write-Host "4. This applies to ALL Blazor Server apps with Keycloak" -ForegroundColor White
    
    Write-Host "NEXT STEPS:" -ForegroundColor Green
    Write-Host "1. Update your appsettings.json with the configuration above" -ForegroundColor White
    Write-Host "2. Ensure UsePkce = false in both appsettings.json AND Startup.cs" -ForegroundColor White
    Write-Host "3. Restart your Blazor Server application" -ForegroundColor White
    Write-Host "4. Test authentication - the 'unauthorized_client' error should be gone!" -ForegroundColor White
    
    Write-Host "New Client Secret: $clientSecret" -ForegroundColor Green
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