# Keycloak Setup Script for XafKeycloakAuth
# This script sets up Keycloak realm and client for the XAF application
# 
# Prerequisites:
# - Keycloak running at http://localhost:8080
# - Admin credentials: Admin / JoseManuel16
# - PowerShell 5.1+ with Invoke-RestMethod support

param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUser = "Admin",
    [string]$AdminPassword = "JoseManuel16",
    [string]$RealmName = "XafKeycloakAuth",
    [string]$ClientId = "xaf-keycloak-auth-blazor",
    [string]$BlazorAppUrl = "https://localhost:44318"
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
        Write-Error "Failed to get admin access token: $($_.Exception.Message)"
        throw
    }
}

# Function to create realm
function New-KeycloakRealm {
    param($KeycloakUrl, $AccessToken, $RealmName)
    
    $headers = @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }
    
    $realmConfig = @{
        realm = $RealmName
        displayName = "XAF Keycloak Auth"
        displayNameHtml = "<div class='kc-logo-text'><span>XAF Keycloak Auth</span></div>"
        enabled = $true
        registrationAllowed = $false
        registrationEmailAsUsername = $true
        editUsernameAllowed = $false
        resetPasswordAllowed = $true
        rememberMe = $true
        verifyEmail = $false
        loginWithEmailAllowed = $true
        duplicateEmailsAllowed = $false
        sslRequired = "external"
        loginTheme = "keycloak"
        adminTheme = "keycloak"
        accountTheme = "keycloak"
        emailTheme = "keycloak"
        internationalizationEnabled = $true
        supportedLocales = @("en", "es")
        defaultLocale = "en"
        accessTokenLifespan = 3600
        accessTokenLifespanForImplicitFlow = 900
        ssoSessionIdleTimeout = 1800
        ssoSessionMaxLifespan = 36000
        offlineSessionIdleTimeout = 2592000
        offlineSessionMaxLifespanEnabled = $false
        clientAuthenticationFlow = "browser"
        directGrantFlow = "direct grant"
        dockerAuthenticationFlow = "docker auth"
        attributes = @{
            "frontendUrl" = $KeycloakUrl
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        # Check if realm exists
        $existingRealm = $null
        try {
            $existingRealm = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName" -Headers $headers -Method Get
        }
        catch {
            # Realm doesn't exist, which is expected
        }
        
        if ($existingRealm) {
            Write-Warning "Realm '$RealmName' already exists. Skipping realm creation."
            return $true
        }
        
        Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms" -Headers $headers -Method Post -Body $realmConfig
        Write-Host "Realm '$RealmName' created successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to create realm: $($_.Exception.Message)"
        return $false
    }
}

# Function to create client
function New-KeycloakClient {
    param($KeycloakUrl, $AccessToken, $RealmName, $ClientId, $BlazorAppUrl)
    
    $headers = @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }
    
    $clientConfig = @{
        clientId = $ClientId
        name = "XAF Keycloak Auth Blazor Application"
        description = "XAF Blazor Server application with Keycloak authentication"
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
        nodeReRegistrationTimeout = -1
        rootUrl = $BlazorAppUrl
        adminUrl = "$BlazorAppUrl/admin"
        baseUrl = $BlazorAppUrl
        surrogateAuthRequired = $false
        clientAuthenticatorType = "client-secret"
        redirectUris = @(
            "$BlazorAppUrl/*",
            "$BlazorAppUrl/signin-keycloak",
            "$BlazorAppUrl/auth/callback"
        )
        webOrigins = @(
            $BlazorAppUrl
        )
        notBefore = 0
        defaultClientScopes = @("web-origins", "role_list", "profile", "roles", "email")
        optionalClientScopes = @("address", "phone", "offline_access", "microprofile-jwt")
        attributes = @{
            "saml.assertion.signature" = "false"
            "saml.force.post.binding" = "false"
            "saml.multivalued.roles" = "false"
            "saml.encrypt" = "false"
            "saml.server.signature" = "false"
            "saml.server.signature.keyinfo.ext" = "false"
            "exclude.session.state.from.auth.response" = "false"
            "saml_force_name_id_format" = "false"
            "saml.client.signature" = "false"
            "tls.client.certificate.bound.access.tokens" = "false"
            "saml.authnstatement" = "false"
            "display.on.consent.screen" = "false"
            "saml.onetimeuse.condition" = "false"
            "pkce.code.challenge.method" = "S256"
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        # Check if client exists
        $existingClients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers $headers -Method Get
        
        if ($existingClients -and $existingClients.Count -gt 0) {
            Write-Warning "Client '$ClientId' already exists. Skipping client creation."
            return $existingClients[0].id
        }
        
        $response = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Headers $headers -Method Post -Body $clientConfig
        Write-Host "Client '$ClientId' created successfully" -ForegroundColor Green
        
        # Get the client ID (UUID) for the created client
        $clients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers $headers -Method Get
        return $clients[0].id
    }
    catch {
        Write-Error "Failed to create client: $($_.Exception.Message)"
        return $null
    }
}

# Function to get client secret
function Get-ClientSecret {
    param($KeycloakUrl, $AccessToken, $RealmName, $ClientUuid)
    
    $headers = @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$ClientUuid/client-secret" -Headers $headers -Method Get
        return $response.value
    }
    catch {
        Write-Error "Failed to get client secret: $($_.Exception.Message)"
        return $null
    }
}

# Function to create default users
function New-DefaultUsers {
    param($KeycloakUrl, $AccessToken, $RealmName)
    
    $headers = @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }
    
    $users = @(
        @{
            username = "admin"
            email = "admin@xafkeycloakauth.local"
            firstName = "System"
            lastName = "Administrator"
            enabled = $true
            emailVerified = $true
            credentials = @(
                @{
                    type = "password"
                    value = "admin123"
                    temporary = $false
                }
            )
        },
        @{
            username = "user"
            email = "user@xafkeycloakauth.local"
            firstName = "Test"
            lastName = "User"
            enabled = $true
            emailVerified = $true
            credentials = @(
                @{
                    type = "password"
                    value = "user123"
                    temporary = $false
                }
            )
        }
    )
    
    foreach ($user in $users) {
        try {
            # Check if user exists
            $existingUsers = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/users?username=$($user.username)" -Headers $headers -Method Get
            
            if ($existingUsers -and $existingUsers.Count -gt 0) {
                Write-Warning "User '$($user.username)' already exists. Skipping user creation."
                continue
            }
            
            $userJson = $user | ConvertTo-Json -Depth 10
            Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/users" -Headers $headers -Method Post -Body $userJson
            Write-Host "User '$($user.username)' created successfully" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to create user '$($user.username)': $($_.Exception.Message)"
        }
    }
}

# Main script execution
try {
    Write-Host "Starting Keycloak setup for XafKeycloakAuth..." -ForegroundColor Cyan
    Write-Host "Keycloak URL: $KeycloakUrl" -ForegroundColor Gray
    Write-Host "Realm Name: $RealmName" -ForegroundColor Gray
    Write-Host "Client ID: $ClientId" -ForegroundColor Gray
    Write-Host "Blazor App URL: $BlazorAppUrl" -ForegroundColor Gray
    Write-Host ""
    
    # Step 1: Get admin access token
    Write-Host "Getting admin access token..." -ForegroundColor Yellow
    $accessToken = Get-AdminAccessToken -KeycloakUrl $KeycloakUrl -AdminUser $AdminUser -AdminPassword $AdminPassword
    Write-Host "Admin access token obtained" -ForegroundColor Green
    
    # Step 2: Create realm
    Write-Host "Creating realm '$RealmName'..." -ForegroundColor Yellow
    $realmCreated = New-KeycloakRealm -KeycloakUrl $KeycloakUrl -AccessToken $accessToken -RealmName $RealmName
    
    if (-not $realmCreated) {
        throw "Failed to create realm"
    }
    
    # Step 3: Create client
    Write-Host "Creating client '$ClientId'..." -ForegroundColor Yellow
    $clientUuid = New-KeycloakClient -KeycloakUrl $KeycloakUrl -AccessToken $accessToken -RealmName $RealmName -ClientId $ClientId -BlazorAppUrl $BlazorAppUrl
    
    if (-not $clientUuid) {
        throw "Failed to create client"
    }
    
    # Step 4: Get client secret
    Write-Host "Getting client secret..." -ForegroundColor Yellow
    $clientSecret = Get-ClientSecret -KeycloakUrl $KeycloakUrl -AccessToken $accessToken -RealmName $RealmName -ClientUuid $clientUuid
    
    if (-not $clientSecret) {
        throw "Failed to get client secret"
    }
    
    # Step 5: Create default users
    Write-Host "Creating default users..." -ForegroundColor Yellow
    New-DefaultUsers -KeycloakUrl $KeycloakUrl -AccessToken $accessToken -RealmName $RealmName
    
    # Display configuration summary
    Write-Host ""
    Write-Host "Setup completed successfully!" -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host "Configuration for appsettings.json:" -ForegroundColor Cyan
    Write-Host ""
    
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
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host "Keycloak URLs:" -ForegroundColor Cyan
    Write-Host "• Admin Console: $KeycloakUrl/admin/master/console/" -ForegroundColor White
    Write-Host "• Realm Console: $KeycloakUrl/admin/master/console/#/$RealmName" -ForegroundColor White
    Write-Host "• OpenID Configuration: $KeycloakUrl/realms/$RealmName/.well-known/openid-configuration" -ForegroundColor White
    Write-Host ""
    Write-Host "Test Users:" -ForegroundColor Cyan
    Write-Host "• Username: admin, Password: admin123 (Administrator)" -ForegroundColor White
    Write-Host "• Username: user, Password: user123 (Regular User)" -ForegroundColor White
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "1. Copy the configuration above to your appsettings.json file" -ForegroundColor White
    Write-Host "2. Install Microsoft.AspNetCore.Authentication.OpenIdConnect NuGet package" -ForegroundColor White
    Write-Host "3. Update Startup.cs to configure Keycloak authentication" -ForegroundColor White
    Write-Host "4. Implement the bridge middleware for XAF Security integration" -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    exit 1
}