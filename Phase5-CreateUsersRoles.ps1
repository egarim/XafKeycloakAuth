# Phase 5: Create Users and Roles for XAF Application
# Based on working example patterns, with XAF-appropriate roles

Write-Host "=== PHASE 5: SETTING UP USERS AND ROLES ===" -ForegroundColor Cyan
Write-Host "Creating roles and test users for XAF application..." -ForegroundColor Yellow

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

# Create roles (XAF-appropriate roles)
Write-Host "Creating XAF roles..." -ForegroundColor Yellow
$roles = @("Admin", "User", "Manager")

foreach ($roleName in $roles) {
    $role = @{
        name = $roleName
        description = "XAF Role for $roleName users"
    }
    
    try {
        $jsonBody = $role | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth/roles" -Method Post -Body $jsonBody -Headers $headers
        Write-Host "Role '$roleName' created successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Role '$roleName' already exists or error occurred" -ForegroundColor Yellow
    }
}

# Create test users
Write-Host ""
Write-Host "Creating test users..." -ForegroundColor Yellow

# Admin user
$adminUser = @{
    username = "admin"
    email = "admin@xafkeycloak.com"
    firstName = "XAF"
    lastName = "Administrator"
    enabled = $true
    emailVerified = $true
    credentials = @(
        @{
            type = "password"
            value = "Admin123!"
            temporary = $false
        }
    )
}

try {
    $jsonBody = $adminUser | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth/users" -Method Post -Body $jsonBody -Headers $headers
    Write-Host "Admin user created successfully" -ForegroundColor Green
}
catch {
    Write-Host "Admin user already exists or error occurred" -ForegroundColor Yellow
}

# Regular user
$regularUser = @{
    username = "testuser"
    email = "testuser@xafkeycloak.com"
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
    $jsonBody = $regularUser | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth/users" -Method Post -Body $jsonBody -Headers $headers
    Write-Host "Test user created successfully" -ForegroundColor Green
}
catch {
    Write-Host "Test user already exists or error occurred" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== USERS AND ROLES CONFIGURATION ===" -ForegroundColor Green
Write-Host "Roles Created:" -ForegroundColor Green
Write-Host "  Admin - Full administrative access" -ForegroundColor Gray
Write-Host "  User - Standard user access" -ForegroundColor Gray
Write-Host "  Manager - Management level access" -ForegroundColor Gray
Write-Host ""
Write-Host "Test Users Created:" -ForegroundColor Green
Write-Host "  Username: admin" -ForegroundColor White
Write-Host "  Password: Admin123!" -ForegroundColor White
Write-Host "  Email: admin@xafkeycloak.com" -ForegroundColor Gray
Write-Host ""
Write-Host "  Username: testuser" -ForegroundColor White
Write-Host "  Password: Test123!" -ForegroundColor White
Write-Host "  Email: testuser@xafkeycloak.com" -ForegroundColor Gray
Write-Host ""
Write-Host "Phase 5 Complete - Users and roles configured!" -ForegroundColor Green