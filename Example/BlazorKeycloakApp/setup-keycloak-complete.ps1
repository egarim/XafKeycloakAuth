# Complete Keycloak Setup Script for Blazor Server + Blazor WebAssembly + C# REST API
# This script creates a realm, configures clients, and handles all redirect URI configurations
# 
# Environment Variables (optional):
# - KEYCLOAK_URL: Keycloak server URL (default: http://localhost:8080)
# - KEYCLOAK_ADMIN_USER: Admin username (default: admin)
# - KEYCLOAK_ADMIN_PASSWORD: Admin password (default: admin)
#
# Parameters:
# - RecreateWasmClient: Force recreation of the WebAssembly client if it exists

param(
    [string]$KeycloakUrl = $(if ($env:KEYCLOAK_URL) { $env:KEYCLOAK_URL } else { "http://localhost:8080" }),
    [string]$AdminUsername = $(if ($env:KEYCLOAK_ADMIN_USER) { $env:KEYCLOAK_ADMIN_USER } else { "admin" }),
    [string]$AdminPassword = $(if ($env:KEYCLOAK_ADMIN_PASSWORD) { $env:KEYCLOAK_ADMIN_PASSWORD } else { "admin" }),
    [string]$RealmName = "blazor-app",
    [string]$BlazorClientId = "blazor-server",
    [string]$BlazorWasmClientId = "blazor-wasm",
    [string]$ApiClientId = "blazor-api",
    [string]$BlazorBaseUrl = "https://localhost:7001",
    [string]$BlazorWasmBaseUrl = "https://localhost:7003",
    [string]$ApiBaseUrl = "https://localhost:7049",
    [switch]$UpdateOnly = $false,
    [switch]$ShowInstructions = $false,
    [switch]$RecreateWasmClient = $false
)

# Function to get admin access token
function Get-AdminToken {
    param($KeycloakUrl, $Username, $Password)
    
    $tokenUrl = "$KeycloakUrl/realms/master/protocol/openid-connect/token"
    $body = @{
        grant_type = "password"
        client_id = "admin-cli"
        username = $Username
        password = $Password
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-Error "Failed to get admin token: $($_.Exception.Message)"
        Write-Host ""
        Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
        Write-Host "1. Verify Keycloak is running at: $KeycloakUrl" -ForegroundColor Gray
        Write-Host "2. Check admin credentials (default: admin/admin)" -ForegroundColor Gray
        Write-Host "3. Ensure Keycloak admin console is accessible" -ForegroundColor Gray
        Write-Host ""
        exit 1
    }
}

# Function to make authenticated API calls
function Invoke-KeycloakApi {
    param($Uri, $Method = "GET", $Body = $null, $Token)
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    
    try {
        if ($Body) {
            $jsonBody = $Body | ConvertTo-Json -Depth 10
            return Invoke-RestMethod -Uri $Uri -Method $Method -Body $jsonBody -Headers $headers
        }
        else {
            return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $headers
        }
    }
    catch {
        Write-Warning "API call failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            Write-Warning "Response: $responseBody"
        }
        throw
    }
}

# Function to create realm
function New-Realm {
    param($RealmName, $KeycloakUrl, $Token)
    
    $realm = @{
        realm = $RealmName
        enabled = $true
        displayName = "Blazor Application Realm"
        registrationAllowed = $false
        loginWithEmailAllowed = $true
        duplicateEmailsAllowed = $false
        resetPasswordAllowed = $true
        editUsernameAllowed = $false
        bruteForceProtected = $true
        accessTokenLifespan = 300
        accessTokenLifespanForImplicitFlow = 900
        ssoSessionIdleTimeout = 1800
        ssoSessionMaxLifespan = 36000
        offlineSessionIdleTimeout = 2592000
        accessCodeLifespan = 60
        accessCodeLifespanUserAction = 300
        accessCodeLifespanLogin = 1800
        actionTokenGeneratedByAdminLifespan = 43200
        actionTokenGeneratedByUserLifespan = 300
    }
    
    try {
        Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms" -Method Post -Body $realm -Token $Token
        Write-Host "Realm '$RealmName' created successfully" -ForegroundColor Green
        return $true
    }
    catch {
        if ($_.Exception.Message -like "*409*") {
            Write-Host "Realm '$RealmName' already exists" -ForegroundColor Yellow
            return $true
        }
        else {
            Write-Error "Failed to create realm: $($_.Exception.Message)"
            return $false
        }
    }
}

# Function to create Blazor Server client
function New-BlazorClient {
    param($RealmName, $ClientId, $BaseUrl, $KeycloakUrl, $Token)
    
    $redirectUris = @(
        "$BaseUrl/",
        "$BaseUrl/signin-oidc",
        "$BaseUrl/authentication/login-callback",
        "https://localhost:7001/",
        "https://localhost:7001/signin-oidc",
        "https://localhost:7001/authentication/login-callback"
    )
    
    $postLogoutRedirectUris = @(
        "$BaseUrl/",
        "$BaseUrl/authentication/logout-callback",
        "$BaseUrl/signout-callback-oidc",
        "https://localhost:7001/",
        "https://localhost:7001/authentication/logout-callback",
        "https://localhost:7001/signout-callback-oidc"
    )
    
    $client = @{
        clientId = $ClientId
        name = "Blazor Server Application"
        description = "OpenID Connect client for Blazor Server"
        enabled = $true
        clientAuthenticatorType = "client-secret"
        secret = "your-blazor-client-secret-here"
        redirectUris = $redirectUris
        webOrigins = @("$BaseUrl", "https://localhost:7001")
        protocol = "openid-connect"
        publicClient = $false
        frontchannelLogout = $true
        attributes = @{
            "pkce.code.challenge.method" = "S256"
            "post.logout.redirect.uris" = ($postLogoutRedirectUris -join "##")
        }
        standardFlowEnabled = $true
        implicitFlowEnabled = $false
        directAccessGrantsEnabled = $false
        serviceAccountsEnabled = $false
        fullScopeAllowed = $true
    }
    
    try {
        $response = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Method Post -Body $client -Token $Token
        Write-Host "Blazor client '$ClientId' created successfully" -ForegroundColor Green
        
        # Get the client UUID for further configuration
        $clients = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Token $Token
        $clientUuid = $clients[0].id
        
        # Add audience mapper
        Add-AudienceMapper -RealmName $RealmName -ClientUuid $clientUuid -KeycloakUrl $KeycloakUrl -Token $Token
        
        return $clientUuid
    }
    catch {
        if ($_.Exception.Message -like "*409*") {
            Write-Host "Blazor client '$ClientId' already exists" -ForegroundColor Yellow
            $clients = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Token $Token
            return $clients[0].id
        }
        else {
            Write-Error "Failed to create Blazor client: $($_.Exception.Message)"
            return $null
        }
    }
}

# Function to create API client
function New-ApiClient {
    param($RealmName, $ClientId, $BaseUrl, $KeycloakUrl, $Token)
    
    $client = @{
        clientId = $ClientId
        name = "Blazor API"
        description = "JWT Bearer client for Blazor API"
        enabled = $true
        clientAuthenticatorType = "client-secret"
        secret = "your-api-client-secret-here"
        protocol = "openid-connect"
        publicClient = $false
        bearerOnly = $true
        standardFlowEnabled = $false
        implicitFlowEnabled = $false
        directAccessGrantsEnabled = $false
        serviceAccountsEnabled = $false
        fullScopeAllowed = $true
        attributes = @{
            "access.token.lifespan" = "300"
        }
    }
    
    try {
        Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Method Post -Body $client -Token $Token
        Write-Host "API client '$ClientId' created successfully" -ForegroundColor Green
        return $true
    }
    catch {
        if ($_.Exception.Message -like "*409*") {
            Write-Host "API client '$ClientId' already exists" -ForegroundColor Yellow
            return $true
        }
        else {
            Write-Error "Failed to create API client: $($_.Exception.Message)"
            return $false
        }
    }
}

# Function to delete a client (if needed for cleanup)
function Remove-KeycloakClient {
    param($RealmName, $ClientId, $KeycloakUrl, $Token)
    
    try {
        # Get client UUID first
        $clients = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Token $Token
        if ($clients.Count -gt 0) {
            $clientUuid = $clients[0].id
            Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$clientUuid" -Method Delete -Token $Token
            Write-Host "Client '$ClientId' deleted successfully" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "Client '$ClientId' not found" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Warning "Failed to delete client '$ClientId': $($_.Exception.Message)"
        return $false
    }
}

# Function to create Blazor WebAssembly client
function New-BlazorWasmClient {
    param($RealmName, $ClientId, $BaseUrl, $KeycloakUrl, $Token)
    
    $redirectUris = @(
        "$BaseUrl/authentication/login-callback",
        "https://localhost:7003/authentication/login-callback"
    )
    
    $postLogoutRedirectUris = @(
        "$BaseUrl/authentication/logout-callback", 
        "https://localhost:7003/authentication/logout-callback"
    )
    
    $client = @{
        clientId = $ClientId
        name = "Blazor WebAssembly Application"
        description = "OpenID Connect client for Blazor WebAssembly"
        enabled = $true
        # Public clients don't have client authenticator type or secret
        redirectUris = $redirectUris
        webOrigins = @("$BaseUrl", "https://localhost:7003")
        protocol = "openid-connect"
        publicClient = $true  # WebAssembly is a public client
        frontchannelLogout = $true
        attributes = @{
            "pkce.code.challenge.method" = "S256"
            "oauth2.device.authorization.grant.enabled" = "false"
            "oidc.ciba.grant.enabled" = "false"
        }
        standardFlowEnabled = $true
        implicitFlowEnabled = $false
        directAccessGrantsEnabled = $false
        serviceAccountsEnabled = $false
        fullScopeAllowed = $false
        # Default client scopes
        defaultClientScopes = @("web-origins", "acr", "profile", "roles", "email")
        optionalClientScopes = @("address", "phone", "offline_access", "microprofile-jwt")
    }
    
    try {
        $response = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Method Post -Body $client -Token $Token
        Write-Host "Blazor WebAssembly client '$ClientId' created successfully" -ForegroundColor Green
        
        # Get the client UUID for further configuration
        $clients = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Token $Token
        $clientUuid = $clients[0].id
        
        # Add audience mapper for WebAssembly client
        Add-AudienceMapper -RealmName $RealmName -ClientUuid $clientUuid -KeycloakUrl $KeycloakUrl -Token $Token
        
        return $clientUuid
    }
    catch {
        if ($_.Exception.Message -like "*409*") {
            Write-Host "Blazor WebAssembly client '$ClientId' already exists" -ForegroundColor Yellow
            # Get existing client UUID
            try {
                $clients = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Token $Token
                return $clients[0].id
            }
            catch {
                Write-Warning "Could not retrieve existing WebAssembly client UUID"
                return $null
            }
        }
        else {
            Write-Error "Failed to create Blazor WebAssembly client: $($_.Exception.Message)"
            return $null
        }
    }
}

# Function to add audience mapper
function Add-AudienceMapper {
    param($RealmName, $ClientUuid, $KeycloakUrl, $Token)
    
    $audienceMapper = @{
        name = "audience-mapper"
        protocol = "openid-connect"
        protocolMapper = "oidc-audience-mapper"
        consentRequired = $false
        config = @{
            "included.client.audience" = "blazor-api"
            "id.token.claim" = "false"
            "access.token.claim" = "true"
        }
    }
    
    try {
        Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$ClientUuid/protocol-mappers/models" -Method Post -Body $audienceMapper -Token $Token
        Write-Host "Audience mapper added successfully" -ForegroundColor Green
        return $true
    }
    catch {
        if ($_.Exception.Message -like "*409*") {
            Write-Host "Audience mapper already exists" -ForegroundColor Yellow
            return $true
        }
        else {
            Write-Warning "Failed to create audience mapper: $($_.Exception.Message)"
            return $false
        }
    }
}

# Function to create roles
function New-Roles {
    param($RealmName, $KeycloakUrl, $Token)
    
    $roles = @("admin", "user")
    
    foreach ($roleName in $roles) {
        $role = @{
            name = $roleName
            description = "Role for $roleName users"
        }
        
        try {
            Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/roles" -Method Post -Body $role -Token $Token
            Write-Host "Role '$roleName' created successfully" -ForegroundColor Green
        }
        catch {
            if ($_.Exception.Message -like "*409*") {
                Write-Host "Role '$roleName' already exists" -ForegroundColor Yellow
            }
            else {
                Write-Warning "Failed to create role '$roleName': $($_.Exception.Message)"
            }
        }
    }
}

# Function to create test user
function New-TestUser {
    param($RealmName, $KeycloakUrl, $Token)
    
    $user = @{
        username = "testuser"
        email = "testuser@example.com"
        firstName = "Test"
        lastName = "User"
        enabled = $true
        emailVerified = $true
        credentials = @(
            @{
                type = "password"
                value = "Test123!"
                temporary = $false
            }
        )
    }
    
    try {
        Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/users" -Method Post -Body $user -Token $Token
        Write-Host "Test user 'testuser' created successfully" -ForegroundColor Green
        
        # Get user ID and assign roles
        $users = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/users?username=testuser" -Token $Token
        $userId = $users[0].id
        
        # Assign roles
        $adminRole = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/roles/admin" -Token $Token
        $userRole = Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/roles/user" -Token $Token
        
        $rolesToAssign = @($adminRole, $userRole)
        
        Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName/users/$userId/role-mappings/realm" -Method Post -Body $rolesToAssign -Token $Token
        Write-Host "Roles assigned to test user" -ForegroundColor Green
        
        return $true
    }
    catch {
        if ($_.Exception.Message -like "*409*") {
            Write-Host "Test user 'testuser' already exists" -ForegroundColor Yellow
            return $true
        }
        else {
            Write-Warning "Failed to create test user: $($_.Exception.Message)"
            return $false
        }
    }
}

# Main script execution
Write-Host "Complete Keycloak Setup Script" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

if ($ShowInstructions) {
    Write-Host "Manual Setup Instructions:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Access Keycloak Admin Console: $KeycloakUrl/admin" -ForegroundColor Gray
    Write-Host "2. Login with admin credentials" -ForegroundColor Gray
    Write-Host "3. Create realm: $RealmName" -ForegroundColor Gray
    Write-Host "4. Create client: $BlazorClientId (OpenID Connect)" -ForegroundColor Gray
    Write-Host "5. Create client: $ApiClientId (Bearer-only)" -ForegroundColor Gray
    Write-Host "6. Configure redirect URIs and audience mapper" -ForegroundColor Gray
    Write-Host "7. Create roles: admin, user" -ForegroundColor Gray
    Write-Host "8. Create test user: testuser / Test123!" -ForegroundColor Gray
    Write-Host ""
    exit 0
}

Write-Host "Connecting to Keycloak at: $KeycloakUrl" -ForegroundColor Yellow
Write-Host "Realm: $RealmName" -ForegroundColor Gray
Write-Host "Blazor Server Client: $BlazorClientId" -ForegroundColor Gray
Write-Host "Blazor WebAssembly Client: $BlazorWasmClientId" -ForegroundColor Gray
Write-Host "API Client: $ApiClientId" -ForegroundColor Gray
Write-Host ""

# Get admin token
Write-Host "Getting admin access token..." -ForegroundColor Yellow
$adminToken = Get-AdminToken -KeycloakUrl $KeycloakUrl -Username $AdminUsername -Password $AdminPassword

if (-not $UpdateOnly) {
    # Create realm
    Write-Host "Creating realm..." -ForegroundColor Yellow
    $realmCreated = New-Realm -RealmName $RealmName -KeycloakUrl $KeycloakUrl -Token $adminToken
    
    if (-not $realmCreated) {
        Write-Error "Failed to create realm. Exiting."
        exit 1
    }
    
    # Create roles
    Write-Host "Creating roles..." -ForegroundColor Yellow
    New-Roles -RealmName $RealmName -KeycloakUrl $KeycloakUrl -Token $adminToken
}

# Create/update clients
Write-Host "Creating Blazor Server client..." -ForegroundColor Yellow
$blazorClientUuid = New-BlazorClient -RealmName $RealmName -ClientId $BlazorClientId -BaseUrl $BlazorBaseUrl -KeycloakUrl $KeycloakUrl -Token $adminToken

Write-Host "Creating Blazor WebAssembly client..." -ForegroundColor Yellow
if ($RecreateWasmClient) {
    Write-Host "RecreateWasmClient flag set - removing existing WebAssembly client first..." -ForegroundColor Yellow
    Remove-KeycloakClient -RealmName $RealmName -ClientId $BlazorWasmClientId -KeycloakUrl $KeycloakUrl -Token $adminToken
}
$blazorWasmClientUuid = New-BlazorWasmClient -RealmName $RealmName -ClientId $BlazorWasmClientId -BaseUrl $BlazorWasmBaseUrl -KeycloakUrl $KeycloakUrl -Token $adminToken

Write-Host "Creating API client..." -ForegroundColor Yellow
$apiClientCreated = New-ApiClient -RealmName $RealmName -ClientId $ApiClientId -BaseUrl $ApiBaseUrl -KeycloakUrl $KeycloakUrl -Token $adminToken

if (-not $UpdateOnly) {
    # Create test user
    Write-Host "Creating test user..." -ForegroundColor Yellow
    New-TestUser -RealmName $RealmName -KeycloakUrl $KeycloakUrl -Token $adminToken
}

Write-Host ""
Write-Host "Setup completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration Summary:" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host "Keycloak URL: $KeycloakUrl" -ForegroundColor Gray
Write-Host "Realm: $RealmName" -ForegroundColor Gray
Write-Host "Blazor Server Client ID: $BlazorClientId" -ForegroundColor Gray
Write-Host "Blazor WebAssembly Client ID: $BlazorWasmClientId" -ForegroundColor Gray
Write-Host "API Client ID: $ApiClientId" -ForegroundColor Gray
Write-Host "Test User: testuser / Test123!" -ForegroundColor Gray
Write-Host ""
Write-Host "IMPORTANT: Manual Configuration Required" -ForegroundColor Red
Write-Host "=========================================" -ForegroundColor Red
Write-Host ""
Write-Host "1. GET CLIENT SECRET from Keycloak Admin Console:" -ForegroundColor Yellow
Write-Host "   - Open: $KeycloakUrl/admin" -ForegroundColor Gray
Write-Host "   - Navigate to: Realms > $RealmName > Clients > $BlazorClientId" -ForegroundColor Gray
Write-Host "   - Go to 'Credentials' tab" -ForegroundColor Gray
Write-Host "   - Copy the 'Client secret' value" -ForegroundColor Gray
Write-Host ""
Write-Host "2. UPDATE APPSETTINGS.JSON:" -ForegroundColor Yellow
Write-Host "   File: BlazorServer/appsettings.json" -ForegroundColor Gray
Write-Host "   Update the ClientSecret with the value from step 1:" -ForegroundColor Gray
Write-Host ""
Write-Host '   "Keycloak": {' -ForegroundColor Cyan
Write-Host '     "Authority": "http://localhost:8080/realms/blazor-app",' -ForegroundColor Cyan
Write-Host '     "ClientId": "blazor-server",' -ForegroundColor Cyan
Write-Host '     "ClientSecret": "YOUR_ACTUAL_CLIENT_SECRET_HERE",' -ForegroundColor Red
Write-Host '     "RequireHttpsMetadata": false' -ForegroundColor Cyan
Write-Host '   }' -ForegroundColor Cyan
Write-Host ""
Write-Host "3. RUN THE APPLICATIONS:" -ForegroundColor Yellow
Write-Host "   Terminal 1 - API:" -ForegroundColor Gray
Write-Host "   cd BlazorApi && dotnet run" -ForegroundColor Gray
Write-Host ""
Write-Host "   Terminal 2 - Blazor Server:" -ForegroundColor Gray
Write-Host "   cd BlazorServer && dotnet run" -ForegroundColor Gray
Write-Host ""
Write-Host "   Terminal 3 - Blazor WebAssembly:" -ForegroundColor Gray
Write-Host "   cd BlazorWebAssembly && dotnet run" -ForegroundColor Gray
Write-Host ""
Write-Host "4. TEST AUTHENTICATION:" -ForegroundColor Yellow
Write-Host "   Blazor Server: Navigate to: $BlazorBaseUrl" -ForegroundColor Gray
Write-Host "   Blazor WebAssembly: Navigate to: $BlazorWasmBaseUrl" -ForegroundColor Gray
Write-Host "   - Click 'Login' or 'Log in'" -ForegroundColor Gray
Write-Host "   - Use credentials: testuser / Test123!" -ForegroundColor Gray
Write-Host "   - Test API calls on the /api-test page" -ForegroundColor Gray
Write-Host ""
Write-Host "Important: Audience mapper configured for JWT tokens" -ForegroundColor Green
Write-Host "This fixes the 'aud' claim issue for API authentication" -ForegroundColor Green
