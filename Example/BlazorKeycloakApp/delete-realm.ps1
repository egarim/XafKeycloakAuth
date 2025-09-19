# Delete Keycloak Realm Script
# This script safely deletes the blazor-app realm to start fresh
#
# Environment Variables (optional):
# - KEYCLOAK_URL: Keycloak server URL (default: http://localhost:8080)
# - KEYCLOAK_ADMIN_USER: Admin username (default: admin)
# - KEYCLOAK_ADMIN_PASSWORD: Admin password (default: admin)

param(
    [string]$KeycloakUrl = $(if ($env:KEYCLOAK_URL) { $env:KEYCLOAK_URL } else { "http://localhost:8080" }),
    [string]$AdminUsername = $(if ($env:KEYCLOAK_ADMIN_USER) { $env:KEYCLOAK_ADMIN_USER } else { "admin" }), 
    [string]$AdminPassword = $(if ($env:KEYCLOAK_ADMIN_PASSWORD) { $env:KEYCLOAK_ADMIN_PASSWORD } else { "admin" }),
    [string]$RealmName = "blazor-app"
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
        Write-Host "Getting admin token..." -ForegroundColor Yellow
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Host "Admin token obtained successfully" -ForegroundColor Green
        return $response.access_token
    }
    catch {
        Write-Host "Failed to get admin token: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please check your Keycloak admin credentials" -ForegroundColor Yellow
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
            $bodyJson = $Body | ConvertTo-Json -Depth 10
            return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $headers -Body $bodyJson
        } else {
            return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $headers
        }
    }
    catch {
        throw
    }
}

Write-Host "Keycloak Realm Deletion Script" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This will DELETE the '$RealmName' realm and all its data!" -ForegroundColor Red
Write-Host "This includes:" -ForegroundColor Yellow
Write-Host "  - All clients: blazor-server, blazor-api" -ForegroundColor Gray
Write-Host "  - All users: testuser, etc." -ForegroundColor Gray
Write-Host "  - All roles and configurations" -ForegroundColor Gray
Write-Host ""

$confirmation = Read-Host "Are you sure you want to DELETE realm '$RealmName'? Type 'DELETE' to confirm"

if ($confirmation -ne "DELETE") {
    Write-Host "Operation cancelled" -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Authenticating with Keycloak..." -ForegroundColor Yellow
$adminToken = Get-AdminToken -KeycloakUrl $KeycloakUrl -Username $AdminUsername -Password $AdminPassword

Write-Host "Deleting realm '$RealmName'..." -ForegroundColor Red

try {
    Invoke-KeycloakApi -Uri "$KeycloakUrl/admin/realms/$RealmName" -Method DELETE -Token $adminToken
    Write-Host "Realm '$RealmName' deleted successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "1. Run the setup script to create everything fresh:" -ForegroundColor Gray
    Write-Host "   .\setup-keycloak-complete.ps1" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "2. The setup will create:" -ForegroundColor Gray
    Write-Host "   - Fresh realm with all configurations" -ForegroundColor Gray
    Write-Host "   - Proper audience mapper for JWT issues" -ForegroundColor Gray
    Write-Host "   - Test user with admin and user roles" -ForegroundColor Gray
    Write-Host ""
}
catch {
    if ($_.Exception.Message -like "*404*") {
        Write-Host "Realm '$RealmName' does not exist" -ForegroundColor Yellow
    }
    else {
        Write-Host "Failed to delete realm: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}
