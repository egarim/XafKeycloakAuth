# PKCE + Confidential Client Conflict Fix Script
# This script specifically addresses the common Blazor Server authentication issue
# where PKCE is enabled on a confidential client, causing 'unauthorized_client' errors

param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUser = "Admin",
    [string]$AdminPassword = "JoseManuel16",
    [string]$RealmName = "XafKeycloakAuth",
    [string]$ClientId = "xaf-keycloak-auth-blazor"
)

Write-Host "🔍 PKCE + Confidential Client Conflict Analysis & Fix" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

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
        Write-Error "❌ Failed to get admin token: $($_.Exception.Message)"
        return $null
    }
}

# Get admin token
Write-Host "🔑 Getting admin access token..." -ForegroundColor Yellow
$adminToken = Get-AdminAccessToken -KeycloakUrl $KeycloakUrl -AdminUser $AdminUser -AdminPassword $AdminPassword

if (-not $adminToken) {
    Write-Error "❌ Authentication failed. Cannot proceed."
    exit 1
}

try {
    $headers = @{
        Authorization = "Bearer $adminToken"
        "Content-Type" = "application/json"
    }
    
    # Get current client configuration
    Write-Host "📋 Analyzing current client configuration..." -ForegroundColor Yellow
    $clients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Headers $headers -Method Get
    $client = $clients | Where-Object { $_.clientId -eq $ClientId }
    
    if (-not $client) {
        Write-Error "❌ Client '$ClientId' not found in realm '$RealmName'"
        exit 1
    }
    
    # Analyze the conflict
    Write-Host "`n🔍 CONFLICT ANALYSIS:" -ForegroundColor Red
    Write-Host "Client ID: $($client.clientId)" -ForegroundColor White
    Write-Host "Client Type: $(if ($client.publicClient) { 'Public' } else { 'Confidential' })" -ForegroundColor White
    Write-Host "Client Authenticator: $($client.clientAuthenticatorType)" -ForegroundColor White
    
    $pkceMethod = $client.attributes.'pkce.code.challenge.method'
    if ($pkceMethod) {
        Write-Host "PKCE Method: $pkceMethod" -ForegroundColor Red
        Write-Host "❌ PROBLEM DETECTED: PKCE is ENABLED on a CONFIDENTIAL client!" -ForegroundColor Red
        Write-Host "   This is the root cause of 'unauthorized_client' errors in Blazor Server apps." -ForegroundColor Red
    } else {
        Write-Host "PKCE Method: Not set (disabled)" -ForegroundColor Green
    }
    
    Write-Host "`n📚 WHY THIS CAUSES ISSUES:" -ForegroundColor Cyan
    Write-Host "• PKCE (Proof Key for Code Exchange) is designed for PUBLIC clients" -ForegroundColor White
    Write-Host "• PUBLIC clients cannot securely store client secrets" -ForegroundColor White
    Write-Host "• CONFIDENTIAL clients (like Blazor Server) CAN store secrets securely" -ForegroundColor White
    Write-Host "• Using BOTH PKCE + Client Secret creates authentication conflicts" -ForegroundColor White
    Write-Host "• Keycloak expects either PKCE OR Client Secret, not both" -ForegroundColor White
    
    Write-Host "`n🔧 APPLYING FIX..." -ForegroundColor Yellow
    
    # Fix the client configuration
    $fixedAttributes = @{}
    
    # Copy existing attributes but remove PKCE
    if ($client.attributes) {
        foreach ($attr in $client.attributes.PSObject.Properties) {
            if ($attr.Name -ne "pkce.code.challenge.method") {
                $fixedAttributes[$attr.Name] = $attr.Value
            }
        }
    }
    
    # Explicitly disable PKCE
    $fixedAttributes["pkce.code.challenge.method"] = ""
    
    # Create the update payload
    $updatePayload = @{
        id = $client.id
        clientId = $client.clientId
        name = $client.name
        description = $client.description
        enabled = $true
        protocol = "openid-connect"
        
        # Ensure it's a confidential client
        publicClient = $false
        bearerOnly = $false
        
        # Flow settings
        standardFlowEnabled = $true
        implicitFlowEnabled = $false
        directAccessGrantsEnabled = $true
        serviceAccountsEnabled = $false
        
        # Authentication method
        clientAuthenticatorType = "client-secret"
        
        # Fixed attributes (PKCE disabled)
        attributes = $fixedAttributes
        
        # Keep existing URLs
        redirectUris = $client.redirectUris
        webOrigins = $client.webOrigins
        rootUrl = $client.rootUrl
        baseUrl = $client.baseUrl
        adminUrl = $client.adminUrl
        
        # Keep existing scopes
        defaultClientScopes = $client.defaultClientScopes
        optionalClientScopes = $client.optionalClientScopes
        
        # Other settings
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
    
    Write-Host "✅ Client configuration fixed successfully!" -ForegroundColor Green
    
    # Verification
    Write-Host "`n✅ VERIFICATION:" -ForegroundColor Green
    $updatedClients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers $headers -Method Get
    $updatedClient = $updatedClients[0]
    $updatedPkce = $updatedClient.attributes.'pkce.code.challenge.method'
    
    Write-Host "Client Type: $(if ($updatedClient.publicClient) { 'Public' } else { 'Confidential ✅' })" -ForegroundColor White
    Write-Host "Client Auth: $($updatedClient.clientAuthenticatorType) ✅" -ForegroundColor White
    Write-Host "PKCE Status: $(if ([string]::IsNullOrEmpty($updatedPkce)) { 'Disabled ✅' } else { 'Enabled ❌' })" -ForegroundColor White
    
    # Display configuration for Blazor
    Write-Host "`n🎯 BLAZOR SERVER CONFIGURATION:" -ForegroundColor Cyan
    Write-Host "Use this EXACT configuration in your appsettings.json:" -ForegroundColor Yellow
    
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
                "UsePkce" = $false  # 🔥 CRITICAL: Must be false for confidential clients
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Host $blazorConfig -ForegroundColor White
    
    Write-Host "`n🚨 CRITICAL POINTS FOR BLAZOR SERVER:" -ForegroundColor Red
    Write-Host "1. ClientSecret must be present (confidential client)" -ForegroundColor White
    Write-Host "2. UsePkce MUST be false" -ForegroundColor White
    Write-Host "3. Never use PKCE with confidential clients" -ForegroundColor White
    Write-Host "4. This applies to ALL Blazor Server apps with Keycloak" -ForegroundColor White
    
    Write-Host "`n📋 STARTUP.CS CONFIGURATION:" -ForegroundColor Cyan
    Write-Host "Ensure your OpenID Connect setup looks like this:" -ForegroundColor Yellow
    
    $startupCode = @"
// In Startup.cs or Program.cs
services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options =>
{
    options.Authority = configuration["Authentication:Keycloak:Authority"];
    options.ClientId = configuration["Authentication:Keycloak:ClientId"];
    options.ClientSecret = configuration["Authentication:Keycloak:ClientSecret"]; // REQUIRED
    options.ResponseType = "code";
    options.UsePkce = false; // 🔥 CRITICAL: Must be false
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
});
"@
    
    Write-Host $startupCode -ForegroundColor Gray
    
    Write-Host "`n🎉 NEXT STEPS:" -ForegroundColor Green
    Write-Host "1. Update your appsettings.json with the configuration above" -ForegroundColor White
    Write-Host "2. Ensure UsePkce = false in both appsettings.json AND Startup.cs" -ForegroundColor White
    Write-Host "3. Restart your Blazor Server application" -ForegroundColor White
    Write-Host "4. Test authentication - the 'unauthorized_client' error should be gone!" -ForegroundColor White
    
    # Save configuration
    $blazorConfig | Out-File -FilePath "blazor-keycloak-fixed-config.json" -Encoding UTF8
    Write-Host "`n💾 Configuration saved to blazor-keycloak-fixed-config.json" -ForegroundColor Gray
    
    Write-Host "`n🔍 COMMON BLAZOR + KEYCLOAK MISTAKES:" -ForegroundColor Yellow
    Write-Host "❌ Using public client configuration for Blazor Server" -ForegroundColor Red
    Write-Host "❌ Enabling PKCE on confidential clients" -ForegroundColor Red
    Write-Host "❌ Not setting client secret properly" -ForegroundColor Red
    Write-Host "❌ Inconsistent PKCE settings between Keycloak and app" -ForegroundColor Red
    Write-Host "✅ Use confidential client with client secret and NO PKCE" -ForegroundColor Green
}
catch {
    Write-Error "❌ Failed to fix client configuration: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Error "Response: $responseBody"
    }
    exit 1
}