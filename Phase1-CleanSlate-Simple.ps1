Write-Host "=== PHASE 1: CLEAN SLATE SETUP ===" -ForegroundColor Cyan
Write-Host "Deleting existing realm to start fresh..." -ForegroundColor Yellow

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

# Delete existing realm if it exists
try {
    Write-Host "Checking for existing realm 'XafKeycloakAuth'..."
    Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth" -Headers $headers -Method Get | Out-Null
    
    Write-Host "Found existing realm - deleting..." -ForegroundColor Yellow
    Invoke-RestMethod -Uri "http://localhost:8080/admin/realms/XafKeycloakAuth" -Headers $headers -Method Delete
    Write-Host "✓ Realm 'XafKeycloakAuth' deleted successfully" -ForegroundColor Green
    Write-Host "✓ All clients and configurations removed" -ForegroundColor Green
}
catch {
    if ($_.Exception.Response.StatusCode -eq 404) {
        Write-Host "No existing realm found - starting with clean slate" -ForegroundColor Green
    }
    else {
        Write-Warning "Error: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "=== PHASE 1 COMPLETE ===" -ForegroundColor Green
Write-Host "Clean slate ready for fresh setup" -ForegroundColor White