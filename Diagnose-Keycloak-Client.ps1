# Comprehensive Keycloak Client Diagnostic Script
# This script thoroughly analyzes all possible causes of unauthorized_client errors

param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUser = "Admin",
    [string]$AdminPassword = "JoseManuel16",
    [string]$RealmName = "XafKeycloakAuth",
    [string]$ClientId = "xaf-keycloak-auth-blazor"
)

Write-Host "=== COMPREHENSIVE KEYCLOAK CLIENT DIAGNOSTIC ===" -ForegroundColor Cyan
Write-Host "Analyzing all possible causes of unauthorized_client errors..." -ForegroundColor Yellow

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
Write-Host "1. Getting admin access token..." -ForegroundColor Yellow
$adminToken = Get-AdminAccessToken -KeycloakUrl $KeycloakUrl -AdminUser $AdminUser -AdminPassword $AdminPassword

if (-not $adminToken) {
    Write-Error "Cannot proceed without admin token"
    exit 1
}

try {
    $headers = @{
        Authorization = "Bearer $adminToken"
        "Content-Type" = "application/json"
    }
    
    # Get client details
    Write-Host "2. Fetching client configuration..." -ForegroundColor Yellow
    $clients = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients" -Headers $headers -Method Get
    $client = $clients | Where-Object { $_.clientId -eq $ClientId }
    
    if (-not $client) {
        Write-Error "Client '$ClientId' not found in realm '$RealmName'"
        exit 1
    }
    
    Write-Host "3. DETAILED CLIENT ANALYSIS:" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Gray
    
    # Basic client info
    Write-Host "CLIENT BASIC INFO:" -ForegroundColor White
    Write-Host "  Name: $($client.name)" -ForegroundColor Gray
    Write-Host "  ID: $($client.clientId)" -ForegroundColor Gray
    Write-Host "  UUID: $($client.id)" -ForegroundColor Gray
    Write-Host "  Enabled: $($client.enabled)" -ForegroundColor Gray
    Write-Host "  Protocol: $($client.protocol)" -ForegroundColor Gray
    
    # Client type analysis
    Write-Host "`nCLIENT TYPE ANALYSIS:" -ForegroundColor White
    $clientType = if ($client.publicClient) { "Public" } else { "Confidential" }
    $typeColor = if ($client.publicClient) { "Red" } else { "Green" }
    Write-Host "  Client Type: $clientType" -ForegroundColor $typeColor
    Write-Host "  Public Client: $($client.publicClient)" -ForegroundColor Gray
    Write-Host "  Bearer Only: $($client.bearerOnly)" -ForegroundColor Gray
    Write-Host "  Client Authenticator: $($client.clientAuthenticatorType)" -ForegroundColor Gray
    
    # Flow analysis
    Write-Host "`nFLOW CONFIGURATION:" -ForegroundColor White
    Write-Host "  Standard Flow: $($client.standardFlowEnabled)" -ForegroundColor $(if ($client.standardFlowEnabled) { "Green" } else { "Red" })
    Write-Host "  Implicit Flow: $($client.implicitFlowEnabled)" -ForegroundColor $(if ($client.implicitFlowEnabled) { "Yellow" } else { "Green" })
    Write-Host "  Direct Access Grants: $($client.directAccessGrantsEnabled)" -ForegroundColor Gray
    Write-Host "  Service Accounts: $($client.serviceAccountsEnabled)" -ForegroundColor Gray
    
    # URLs analysis
    Write-Host "`nURL CONFIGURATION:" -ForegroundColor White
    Write-Host "  Root URL: $($client.rootUrl)" -ForegroundColor Gray
    Write-Host "  Base URL: $($client.baseUrl)" -ForegroundColor Gray
    Write-Host "  Admin URL: $($client.adminUrl)" -ForegroundColor Gray
    
    Write-Host "`nREDIRECT URIS:" -ForegroundColor White
    if ($client.redirectUris) {
        foreach ($uri in $client.redirectUris) {
            Write-Host "  - $uri" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No redirect URIs configured!" -ForegroundColor Red
    }
    
    Write-Host "`nWEB ORIGINS:" -ForegroundColor White
    if ($client.webOrigins) {
        foreach ($origin in $client.webOrigins) {
            Write-Host "  - $origin" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No web origins configured!" -ForegroundColor Red
    }
    
    # PKCE analysis
    Write-Host "`nPKCE ANALYSIS:" -ForegroundColor White
    $pkceMethod = $client.attributes.'pkce.code.challenge.method'
    if ($pkceMethod -and $pkceMethod -ne "") {
        Write-Host "  PKCE Method: $pkceMethod" -ForegroundColor Red
        Write-Host "  STATUS: PKCE ENABLED - This is likely the problem!" -ForegroundColor Red
    } else {
        Write-Host "  PKCE Method: Disabled" -ForegroundColor Green
        Write-Host "  STATUS: PKCE correctly disabled" -ForegroundColor Green
    }
    
    # Client secret analysis
    Write-Host "`nCLIENT SECRET ANALYSIS:" -ForegroundColor White
    try {
        $secretResponse = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName/clients/$($client.id)/client-secret" -Headers $headers -Method Get
        $clientSecret = $secretResponse.value
        if ($clientSecret) {
            Write-Host "  Secret Status: Present" -ForegroundColor Green
            Write-Host "  Secret Value: $clientSecret" -ForegroundColor Gray
        } else {
            Write-Host "  Secret Status: Missing!" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  Secret Status: Cannot retrieve (might be missing)" -ForegroundColor Red
    }
    
    # Advanced attributes analysis
    Write-Host "`nADVANCED ATTRIBUTES:" -ForegroundColor White
    if ($client.attributes) {
        foreach ($attr in $client.attributes.PSObject.Properties) {
            $valueColor = if ($attr.Name -eq "pkce.code.challenge.method" -and $attr.Value -ne "") { "Red" } else { "Gray" }
            Write-Host "  $($attr.Name): $($attr.Value)" -ForegroundColor $valueColor
        }
    } else {
        Write-Host "  No advanced attributes set" -ForegroundColor Gray
    }
    
    # Scopes analysis
    Write-Host "`nSCOPES CONFIGURATION:" -ForegroundColor White
    Write-Host "  Default Client Scopes:" -ForegroundColor Gray
    if ($client.defaultClientScopes) {
        foreach ($scope in $client.defaultClientScopes) {
            Write-Host "    - $scope" -ForegroundColor Gray
        }
    }
    Write-Host "  Optional Client Scopes:" -ForegroundColor Gray
    if ($client.optionalClientScopes) {
        foreach ($scope in $client.optionalClientScopes) {
            Write-Host "    - $scope" -ForegroundColor Gray
        }
    }
    
    # PROBLEM IDENTIFICATION
    Write-Host "`n4. PROBLEM IDENTIFICATION:" -ForegroundColor Red
    Write-Host "================================" -ForegroundColor Gray
    
    $problems = @()
    
    # Check for PKCE + Confidential client conflict
    if (-not $client.publicClient -and $pkceMethod -and $pkceMethod -ne "") {
        $problems += "CRITICAL: PKCE enabled on confidential client"
    }
    
    # Check for missing client secret on confidential client
    if (-not $client.publicClient -and -not $clientSecret) {
        $problems += "CRITICAL: No client secret on confidential client"
    }
    
    # Check for missing standard flow
    if (-not $client.standardFlowEnabled) {
        $problems += "ERROR: Standard flow disabled"
    }
    
    # Check for missing redirect URIs
    if (-not $client.redirectUris -or $client.redirectUris.Count -eq 0) {
        $problems += "ERROR: No redirect URIs configured"
    }
    
    # Check if client is disabled
    if (-not $client.enabled) {
        $problems += "ERROR: Client is disabled"
    }
    
    # Check redirect URI format
    $hasValidRedirectUri = $false
    if ($client.redirectUris) {
        foreach ($uri in $client.redirectUris) {
            if ($uri -match "https?://[^/]+/signin-[^/]*") {
                $hasValidRedirectUri = $true
                break
            }
        }
    }
    if (-not $hasValidRedirectUri) {
        $problems += "WARNING: No properly formatted signin redirect URI found"
    }
    
    if ($problems.Count -eq 0) {
        Write-Host "No obvious configuration problems detected!" -ForegroundColor Green
        Write-Host "The issue might be more subtle..." -ForegroundColor Yellow
    } else {
        foreach ($problem in $problems) {
            Write-Host "  ❌ $problem" -ForegroundColor Red
        }
    }
    
    # SOLUTION RECOMMENDATIONS
    Write-Host "`n5. SOLUTION RECOMMENDATIONS:" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Gray
    
    if ($problems -contains "CRITICAL: PKCE enabled on confidential client") {
        Write-Host "FIX 1: Disable PKCE on Keycloak client" -ForegroundColor Yellow
        Write-Host "  - Go to Client Settings > Advanced" -ForegroundColor White
        Write-Host "  - Clear 'Proof Key for Code Exchange Code Challenge Method'" -ForegroundColor White
        Write-Host "  - Save changes" -ForegroundColor White
    }
    
    if ($problems -contains "CRITICAL: No client secret on confidential client") {
        Write-Host "FIX 2: Generate client secret" -ForegroundColor Yellow
        Write-Host "  - Go to Client > Credentials tab" -ForegroundColor White
        Write-Host "  - Click 'Regenerate Secret'" -ForegroundColor White
        Write-Host "  - Copy the new secret to your application configuration" -ForegroundColor White
    }
    
    if ($problems -contains "ERROR: Standard flow disabled") {
        Write-Host "FIX 3: Enable standard flow" -ForegroundColor Yellow
        Write-Host "  - Go to Client Settings" -ForegroundColor White
        Write-Host "  - Enable 'Standard Flow'" -ForegroundColor White
        Write-Host "  - Save changes" -ForegroundColor White
    }
    
    # Test token endpoint
    Write-Host "`n6. TESTING TOKEN ENDPOINT:" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Gray
    
    try {
        if ($clientSecret) {
            Write-Host "Testing client credentials grant..." -ForegroundColor Yellow
            $tokenBody = @{
                grant_type = "client_credentials"
                client_id = $ClientId
                client_secret = $clientSecret
            }
            $tokenResponse = Invoke-RestMethod -Uri "$KeycloakUrl/realms/$RealmName/protocol/openid-connect/token" -Method Post -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
            Write-Host "✅ Client credentials test PASSED" -ForegroundColor Green
            Write-Host "  Token Type: $($tokenResponse.token_type)" -ForegroundColor Gray
            Write-Host "  Expires In: $($tokenResponse.expires_in) seconds" -ForegroundColor Gray
        } else {
            Write-Host "❌ Cannot test token endpoint - no client secret" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "❌ Client credentials test FAILED" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            Write-Host "  Response: $responseBody" -ForegroundColor Red
        }
    }
    
    Write-Host "`n7. RECOMMENDED NEXT STEPS:" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Gray
    Write-Host "1. Apply the fixes identified above" -ForegroundColor White
    Write-Host "2. Restart your application" -ForegroundColor White
    Write-Host "3. Clear browser cache/cookies" -ForegroundColor White
    Write-Host "4. Test authentication again" -ForegroundColor White
    Write-Host "5. If still failing, check Keycloak server logs for more details" -ForegroundColor White
    
}
catch {
    Write-Error "Diagnostic failed: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Error "Response: $responseBody"
    }
    exit 1
}