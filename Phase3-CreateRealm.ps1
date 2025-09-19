# Phase 3: Create XAF Keycloak Realm with Working Configuration
# Based on patterns from the working Blazor example, adapted for XAF Blazor Server

Write-Host "=== PHASE 3: CREATING XAF KEYCLOAK REALM ===" -ForegroundColor Cyan
Write-Host "Creating realm with working example configuration patterns..." -ForegroundColor Yellow

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

Write-Host "Creating XAF realm with optimal settings..." -ForegroundColor Yellow

# Create realm with settings based on working example
$realm = @{
    realm = "XafKeycloakAuth"
    enabled = $true
    displayName = "XAF Keycloak Authentication Realm"
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
    $jsonBody = $realm | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri "http://localhost:8080/admin/realms" -Method Post -Body $jsonBody -Headers $headers
    Write-Host "Realm 'XafKeycloakAuth' created successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create realm: $($_.Exception.Message)"
    exit 1
}

Write-Host ""
Write-Host "=== REALM CONFIGURATION SUMMARY ===" -ForegroundColor Green
Write-Host "Realm Name: XafKeycloakAuth" -ForegroundColor White
Write-Host "Display Name: XAF Keycloak Authentication Realm" -ForegroundColor White
Write-Host "Key Settings:" -ForegroundColor Green
Write-Host "  Access Token Lifespan: 300 seconds (5 minutes)" -ForegroundColor Gray
Write-Host "  SSO Session Idle Timeout: 1800 seconds (30 minutes)" -ForegroundColor Gray
Write-Host "  SSO Session Max Lifespan: 36000 seconds (10 hours)" -ForegroundColor Gray
Write-Host "  Brute Force Protection: Enabled" -ForegroundColor Gray
Write-Host "  Email Login: Enabled" -ForegroundColor Gray
Write-Host "  User Registration: Disabled" -ForegroundColor Gray
Write-Host ""
Write-Host "Phase 3 Complete - Realm created with working patterns!" -ForegroundColor Green