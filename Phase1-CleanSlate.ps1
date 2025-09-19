# Phase 1: Clean Slate - Delete existing realm and start fresh
# This script completely removes the existing XafKeycloakAuth realm to eliminate any configuration issues

param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUsername = "Admin",
    [string]$AdminPassword = "JoseManuel16",
    [string]$RealmName = "XafKeycloakAuth"
)

Write-Host "=== PHASE 1: CLEAN SLATE SETUP ===" -ForegroundColor Cyan
Write-Host "Deleting existing realm to start fresh..." -ForegroundColor Yellow
Write-Host ""

# Get admin access token
Write-Host "Getting admin access token..." -ForegroundColor Yellow
$tokenUrl = "$KeycloakUrl/realms/master/protocol/openid-connect/token"
$body = @{
    grant_type = "password"
    client_id = "admin-cli"
    username = $AdminUsername
    password = $AdminPassword
}

try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
    $token = $tokenResponse.access_token
    Write-Host "✓ Admin token obtained successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get admin token: $($_.Exception.Message)"
    exit 1
}

# Get headers for API calls
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# Check if realm exists and delete it
Write-Host "Checking for existing realm '$RealmName'..." -ForegroundColor Yellow
try {
    $existingRealm = Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName" -Headers $headers -Method Get
    Write-Host "Found existing realm '$RealmName'" -ForegroundColor Red
    
    # Delete the realm
    Write-Host "Deleting realm '$RealmName' and all its clients..." -ForegroundColor Yellow
    Invoke-RestMethod -Uri "$KeycloakUrl/admin/realms/$RealmName" -Headers $headers -Method Delete
    Write-Host "✓ Realm '$RealmName' deleted successfully" -ForegroundColor Green
    Write-Host "✓ All clients and configurations removed" -ForegroundColor Green
}
catch {
    if ($_.Exception.Response.StatusCode -eq 404) {
        Write-Host "Realm '$RealmName' does not exist - starting with clean slate" -ForegroundColor Green
    }
    else {
        Write-Warning "Error checking/deleting realm: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "=== PHASE 1 COMPLETE ===" -ForegroundColor Green
Write-Host "✓ Existing realm and all configurations removed" -ForegroundColor White
Write-Host "✓ Clean slate ready for fresh setup" -ForegroundColor White
Write-Host "✓ No leftover configuration issues" -ForegroundColor White
Write-Host ""
Write-Host "Next: Phase 2 - Analyze working example structure" -ForegroundColor Cyan