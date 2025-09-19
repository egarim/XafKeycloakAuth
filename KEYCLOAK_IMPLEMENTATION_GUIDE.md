# XAF Keycloak Authentication Implementation Guide

This guide provides a complete step-by-step implementation of Keycloak OpenID Connect authentication with DevExpress XAF Blazor Server applications, including proper logout functionality.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Keycloak Setup](#keycloak-setup)
3. [XAF Project Configuration](#xaf-project-configuration)
4. [Authentication Implementation](#authentication-implementation)
5. [Logout Configuration](#logout-configuration)
6. [Testing](#testing)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### Software Requirements
- .NET 9.0 SDK or later
- DevExpress XAF 25.1 or later
- Docker Desktop (for Keycloak)
- PowerShell 5.1 or later
- Visual Studio 2022 or VS Code

### XAF Project Requirements
- XAF Blazor Server application with Security enabled
- Entity Framework Core or XPO data access
- Standard Authentication configured

## Keycloak Setup

### 1. Start Keycloak with Docker

Create a Docker Compose file for Keycloak:

```yaml
# docker-compose.yml
version: '3.8'
services:
  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin123
    ports:
      - "8080:8080"
    command: start-dev
    volumes:
      - keycloak_data:/opt/keycloak/data

volumes:
  keycloak_data:
```

Start Keycloak:
```bash
docker-compose up -d
```

### 2. PowerShell Script for Realm Creation

Save this script as `setup-keycloak-realm.ps1`:

```powershell
# setup-keycloak-realm.ps1
# PowerShell script to create and configure Keycloak realm for XAF authentication

param(
    [string]$KeycloakUrl = "http://localhost:8080",
    [string]$AdminUser = "admin",
    [string]$AdminPassword = "admin123",
    [string]$RealmName = "xaf-realm",
    [string]$ClientId = "xaf-blazor-app",
    [string]$ClientSecret = "your-client-secret",
    [string]$RedirectUri = "https://localhost:5001/signin-oidc",
    [string]$PostLogoutRedirectUri = "https://localhost:5001/signout-callback-oidc"
)

Write-Host "=== XAF Keycloak Realm Setup Script ===" -ForegroundColor Green
Write-Host "Keycloak URL: $KeycloakUrl" -ForegroundColor Cyan
Write-Host "Realm Name: $RealmName" -ForegroundColor Cyan
Write-Host "Client ID: $ClientId" -ForegroundColor Cyan

# Function to get admin token
function Get-AdminToken {
    param($url, $user, $password)
    
    $body = @{
        grant_type = "password"
        client_id = "admin-cli"
        username = $user
        password = $password
    }
    
    try {
        $response = Invoke-RestMethod -Uri "$url/realms/master/protocol/openid-connect/token" -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-Error "Failed to get admin token: $($_.Exception.Message)"
        exit 1
    }
}

# Function to create realm
function New-Realm {
    param($url, $token, $realmName)
    
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    $realmConfig = @{
        realm = $realmName
        enabled = $true
        displayName = "XAF Authentication Realm"
        registrationAllowed = $true
        loginWithEmailAllowed = $true
        duplicateEmailsAllowed = $false
        resetPasswordAllowed = $true
        editUsernameAllowed = $false
        bruteForceProtected = $true
        permanentLockout = $false
        maxFailureWaitSeconds = 900
        minimumQuickLoginWaitSeconds = 60
        waitIncrementSeconds = 60
        quickLoginCheckMilliSeconds = 1000
        maxDeltaTimeSeconds = 43200
        failureFactor = 30
        roles = @{
            realm = @(
                @{
                    name = "user"
                    description = "Standard user role"
                },
                @{
                    name = "admin" 
                    description = "Administrator role"
                }
            )
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        Invoke-RestMethod -Uri "$url/admin/realms" -Method Post -Headers $headers -Body $realmConfig
        Write-Host "✓ Realm '$realmName' created successfully" -ForegroundColor Green
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 409) {
            Write-Host "⚠ Realm '$realmName' already exists" -ForegroundColor Yellow
        }
        else {
            Write-Error "Failed to create realm: $($_.Exception.Message)"
            exit 1
        }
    }
}

# Function to create client
function New-Client {
    param($url, $token, $realmName, $clientId, $clientSecret, $redirectUri, $postLogoutRedirectUri)
    
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    $clientConfig = @{
        clientId = $clientId
        enabled = $true
        protocol = "openid-connect"
        publicClient = $false
        secret = $clientSecret
        standardFlowEnabled = $true
        implicitFlowEnabled = $false
        directAccessGrantsEnabled = $true
        serviceAccountsEnabled = $false
        redirectUris = @($redirectUri, "https://localhost:5001/*")
        webOrigins = @("https://localhost:5001", "http://localhost:5000")
        postLogoutRedirectUris = @($postLogoutRedirectUri, "https://localhost:5001/*")
        frontchannelLogout = $true
        attributes = @{
            "saml.assertion.signature" = "false"
            "saml.force.post.binding" = "false"
            "saml.multivalued.roles" = "false"
            "saml.encrypt" = "false"
            "saml.server.signature" = "false"
            "saml.server.signature.keyinfo.ext" = "false"
            "exclude.session.state.from.auth.response" = "false"
            "oidc.ciba.grant.enabled" = "false"
            "oauth2.device.authorization.grant.enabled" = "false"
            "backchannel.logout.session.required" = "true"
            "backchannel.logout.revoke.offline.tokens" = "false"
        }
        protocolMappers = @(
            @{
                name = "username"
                protocol = "openid-connect"
                protocolMapper = "oidc-usermodel-property-mapper"
                consentRequired = $false
                config = @{
                    "userinfo.token.claim" = "true"
                    "user.attribute" = "username"
                    "id.token.claim" = "true"
                    "access.token.claim" = "true"
                    "claim.name" = "preferred_username"
                    "jsonType.label" = "String"
                }
            },
            @{
                name = "email"
                protocol = "openid-connect"
                protocolMapper = "oidc-usermodel-property-mapper"
                consentRequired = $false
                config = @{
                    "userinfo.token.claim" = "true"
                    "user.attribute" = "email"
                    "id.token.claim" = "true"
                    "access.token.claim" = "true"
                    "claim.name" = "email"
                    "jsonType.label" = "String"
                }
            },
            @{
                name = "given_name"
                protocol = "openid-connect"
                protocolMapper = "oidc-usermodel-property-mapper"
                consentRequired = $false
                config = @{
                    "userinfo.token.claim" = "true"
                    "user.attribute" = "firstName"
                    "id.token.claim" = "true"
                    "access.token.claim" = "true"
                    "claim.name" = "given_name"
                    "jsonType.label" = "String"
                }
            },
            @{
                name = "family_name"
                protocol = "openid-connect"
                protocolMapper = "oidc-usermodel-property-mapper"
                consentRequired = $false
                config = @{
                    "userinfo.token.claim" = "true"
                    "user.attribute" = "lastName"
                    "id.token.claim" = "true"
                    "access.token.claim" = "true"
                    "claim.name" = "family_name"
                    "jsonType.label" = "String"
                }
            }
        )
    } | ConvertTo-Json -Depth 10
    
    try {
        Invoke-RestMethod -Uri "$url/admin/realms/$realmName/clients" -Method Post -Headers $headers -Body $clientConfig
        Write-Host "✓ Client '$clientId' created successfully" -ForegroundColor Green
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 409) {
            Write-Host "⚠ Client '$clientId' already exists" -ForegroundColor Yellow
        }
        else {
            Write-Error "Failed to create client: $($_.Exception.Message)"
            exit 1
        }
    }
}

# Function to create test user
function New-TestUser {
    param($url, $token, $realmName, $username, $password, $email, $firstName, $lastName)
    
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    $userConfig = @{
        username = $username
        enabled = $true
        emailVerified = $true
        firstName = $firstName
        lastName = $lastName
        email = $email
        credentials = @(
            @{
                type = "password"
                value = $password
                temporary = $false
            }
        )
        realmRoles = @("user")
    } | ConvertTo-Json -Depth 10
    
    try {
        Invoke-RestMethod -Uri "$url/admin/realms/$realmName/users" -Method Post -Headers $headers -Body $userConfig
        Write-Host "✓ Test user '$username' created successfully" -ForegroundColor Green
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 409) {
            Write-Host "⚠ User '$username' already exists" -ForegroundColor Yellow
        }
        else {
            Write-Error "Failed to create user: $($_.Exception.Message)"
            exit 1
        }
    }
}

# Main execution
try {
    Write-Host "Step 1: Getting admin token..." -ForegroundColor Yellow
    $adminToken = Get-AdminToken -url $KeycloakUrl -user $AdminUser -password $AdminPassword
    
    Write-Host "Step 2: Creating realm..." -ForegroundColor Yellow
    New-Realm -url $KeycloakUrl -token $adminToken -realmName $RealmName
    
    Write-Host "Step 3: Creating client..." -ForegroundColor Yellow
    New-Client -url $KeycloakUrl -token $adminToken -realmName $RealmName -clientId $ClientId -clientSecret $ClientSecret -redirectUri $RedirectUri -postLogoutRedirectUri $PostLogoutRedirectUri
    
    Write-Host "Step 4: Creating test user..." -ForegroundColor Yellow
    New-TestUser -url $KeycloakUrl -token $adminToken -realmName $RealmName -username "testuser" -password "Test123!" -email "test@example.com" -firstName "Test" -lastName "User"
    
    Write-Host ""
    Write-Host "=== Keycloak Setup Complete! ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "Configuration Details:" -ForegroundColor Cyan
    Write-Host "  Keycloak Admin Console: $KeycloakUrl/admin" -ForegroundColor White
    Write-Host "  Realm: $RealmName" -ForegroundColor White
    Write-Host "  Client ID: $ClientId" -ForegroundColor White
    Write-Host "  Client Secret: $ClientSecret" -ForegroundColor White
    Write-Host "  Authority: $KeycloakUrl/realms/$RealmName" -ForegroundColor White
    Write-Host ""
    Write-Host "Test User Credentials:" -ForegroundColor Cyan
    Write-Host "  Username: testuser" -ForegroundColor White
    Write-Host "  Password: Test123!" -ForegroundColor White
    Write-Host ""
    Write-Host "Next: Configure your XAF application using the appsettings.json section below" -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "Add to appsettings.json:" -ForegroundColor Cyan
    Write-Host @"
{
  "Authentication": {
    "Keycloak": {
      "Authority": "$KeycloakUrl/realms/$RealmName",
      "ClientId": "$ClientId",
      "ClientSecret": "$ClientSecret",
      "RequireHttpsMetadata": "false",
      "ResponseType": "code",
      "CallbackPath": "/signin-oidc",
      "SignedOutCallbackPath": "/signout-callback-oidc",
      "GetClaimsFromUserInfoEndpoint": "true",
      "SaveTokens": "true",
      "UsePkce": "false"
    }
  }
}
"@ -ForegroundColor Gray
}
catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    exit 1
}
```

Run the script:
```powershell
.\setup-keycloak-realm.ps1
```

Or with custom parameters:
```powershell
.\setup-keycloak-realm.ps1 -RealmName "my-realm" -ClientId "my-app" -ClientSecret "my-secret"
```

## XAF Project Configuration

### 1. Install Required NuGet Packages

Add these packages to your `XafKeycloakAuth.Blazor.Server` project:

```xml
<PackageReference Include="Microsoft.AspNetCore.Authentication.OpenIdConnect" Version="9.0.0" />
<PackageReference Include="Microsoft.Identity.Web" Version="3.2.0" />
```

### 2. Update appsettings.json

Add Keycloak configuration:

```json
{
  "Authentication": {
    "Keycloak": {
      "Authority": "http://localhost:8080/realms/xaf-realm",
      "ClientId": "xaf-blazor-app",
      "ClientSecret": "your-client-secret",
      "RequireHttpsMetadata": "false",
      "ResponseType": "code",
      "CallbackPath": "/signin-oidc",
      "SignedOutCallbackPath": "/signout-callback-oidc",
      "GetClaimsFromUserInfoEndpoint": "true",
      "SaveTokens": "true",
      "UsePkce": "false"
    }
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "XafKeycloakAuth.Blazor.Server.Services": "Information"
    }
  }
}
```

## Authentication Implementation

### 1. Create Keycloak Authentication Provider

Create `Services/KeycloakAuthenticationProvider.cs`:

```csharp
using System.Security.Claims;
using System.Security.Principal;
using DevExpress.ExpressApp;
using DevExpress.ExpressApp.Security;
using DevExpress.Persistent.BaseImpl.EF.PermissionPolicy;
using XafKeycloakAuth.Module.BusinessObjects;

namespace XafKeycloakAuth.Blazor.Server.Services;

/// <summary>
/// Custom authentication provider for Keycloak OpenID Connect integration with XAF Security.
/// This bridges ASP.NET Core authentication with XAF's internal security system.
/// </summary>
public class KeycloakAuthenticationProvider : IAuthenticationProviderV2
{
    private readonly IPrincipalProvider principalProvider;

    public KeycloakAuthenticationProvider(IPrincipalProvider principalProvider)
    {
        this.principalProvider = principalProvider;
    }

    public object Authenticate(IObjectSpace objectSpace)
    {
        if (!CanHandlePrincipal(principalProvider.User))
        {
            return null;
        }

        const bool autoCreateUser = true;

        ClaimsPrincipal claimsPrincipal = (ClaimsPrincipal)principalProvider.User;
        
        // Get user identification claims from Keycloak
        var userIdClaim = claimsPrincipal.FindFirst("sub") ?? 
                         claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier) ?? 
                         throw new InvalidOperationException("Unknown user id - missing 'sub' or NameIdentifier claim");

        var providerUserKey = userIdClaim.Value;
        var loginProviderName = claimsPrincipal.Identity.AuthenticationType;
        
        // Try to get username from preferred_username claim (Keycloak standard) or fall back to Name
        var userName = claimsPrincipal.FindFirst("preferred_username")?.Value ?? 
                      claimsPrincipal.Identity.Name ?? 
                      claimsPrincipal.FindFirst(ClaimTypes.Name)?.Value;

        if (string.IsNullOrEmpty(userName))
        {
            throw new InvalidOperationException("Unable to determine username from Keycloak claims");
        }

        // Look for existing user login info
        var userLoginInfo = FindUserLoginInfo(objectSpace, loginProviderName, providerUserKey);
        if (userLoginInfo != null)
        {
            return userLoginInfo.User;
        }

        // Auto-create user if enabled and not found
        if (autoCreateUser)
        {
            return CreateApplicationUser(objectSpace, claimsPrincipal, userName, loginProviderName, providerUserKey);
        }

        return null;
    }

    private bool CanHandlePrincipal(IPrincipal user)
    {
        return user.Identity.IsAuthenticated &&
               user.Identity.AuthenticationType != SecurityDefaults.Issuer &&
               user.Identity.AuthenticationType != SecurityDefaults.PasswordAuthentication &&
               user.Identity.AuthenticationType != SecurityDefaults.WindowsAuthentication &&
               !(user is WindowsPrincipal) &&
               // Check for Keycloak authentication scheme
               (user.Identity.AuthenticationType == "Keycloak" || 
                user.Identity.AuthenticationType == "OpenIdConnect");
    }

    private object CreateApplicationUser(IObjectSpace objectSpace, ClaimsPrincipal claimsPrincipal, 
        string userName, string loginProviderName, string providerUserKey)
    {
        // Check if user already exists by username
        if (objectSpace.FirstOrDefault<ApplicationUser>(user => user.UserName == userName) != null)
        {
            throw new ArgumentException($"The username ('{userName}') was already registered within the system");
        }

        var user = objectSpace.CreateObject<ApplicationUser>();
        user.UserName = userName;
        
        // Set additional user properties from Keycloak claims
        var emailClaim = claimsPrincipal.FindFirst(ClaimTypes.Email) ?? claimsPrincipal.FindFirst("email");
        var givenNameClaim = claimsPrincipal.FindFirst(ClaimTypes.GivenName) ?? claimsPrincipal.FindFirst("given_name");
        var familyNameClaim = claimsPrincipal.FindFirst(ClaimTypes.Surname) ?? claimsPrincipal.FindFirst("family_name");
        var nameClaim = claimsPrincipal.FindFirst("name") ?? claimsPrincipal.FindFirst(ClaimTypes.Name);

        // Try to set properties if they exist on the user object
        SetPropertyIfExists(user, "FirstName", givenNameClaim?.Value);
        SetPropertyIfExists(user, "LastName", familyNameClaim?.Value);
        SetPropertyIfExists(user, "DisplayName", nameClaim?.Value);
        SetPropertyIfExists(user, "Email", emailClaim?.Value);

        // Generate a random password (required by XAF)
        user.SetPassword(Guid.NewGuid().ToString());
        
        // Assign default role
        var defaultRole = objectSpace.FirstOrDefault<PermissionPolicyRole>(role => role.Name == "Default");
        if (defaultRole != null)
        {
            user.Roles.Add(defaultRole);
        }
        else
        {
            // Create a default role if it doesn't exist
            var newDefaultRole = objectSpace.CreateObject<PermissionPolicyRole>();
            newDefaultRole.Name = "Default";
            newDefaultRole.IsAdministrative = false;
            user.Roles.Add(newDefaultRole);
        }

        // Create user login info for this external authentication
        ((ISecurityUserWithLoginInfo)user).CreateUserLoginInfo(loginProviderName, providerUserKey);
        
        objectSpace.CommitChanges();
        return user;
    }

    private ISecurityUserLoginInfo FindUserLoginInfo(IObjectSpace objectSpace, string loginProviderName, string providerUserKey)
    {
        return objectSpace.FirstOrDefault<ApplicationUserLoginInfo>(userLoginInfo =>
                            userLoginInfo.LoginProviderName == loginProviderName &&
                            userLoginInfo.ProviderUserKey == providerUserKey);
    }

    private void SetPropertyIfExists(object obj, string propertyName, string value)
    {
        if (string.IsNullOrEmpty(value)) return;
        
        var property = obj.GetType().GetProperty(propertyName);
        if (property != null && property.CanWrite && property.PropertyType == typeof(string))
        {
            property.SetValue(obj, value);
        }
    }
}
```

### 2. Create Keycloak-XAF Bridge Middleware

Create `Services/KeycloakXafBridgeMiddleware.cs`:

```csharp
using System.Security.Claims;
using DevExpress.ExpressApp.Security;
using DevExpress.ExpressApp.Security.Authentication;

namespace XafKeycloakAuth.Blazor.Server.Services;

/// <summary>
/// Middleware to bridge Keycloak authentication with XAF Security System.
/// This ensures that authenticated Keycloak users are properly recognized by XAF.
/// </summary>
public class KeycloakXafBridgeMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<KeycloakXafBridgeMiddleware> _logger;

    public KeycloakXafBridgeMiddleware(RequestDelegate next, ILogger<KeycloakXafBridgeMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        _logger.LogInformation("KeycloakXafBridgeMiddleware: Processing request for path: {Path}", context.Request.Path);

        // Skip processing for logout paths to prevent interference with logout process
        if (IsLogoutPath(context.Request.Path))
        {
            _logger.LogInformation("KeycloakXafBridgeMiddleware: Skipping logout path: {Path}", context.Request.Path);
            await _next(context);
            return;
        }

        if (context.User?.Identity?.IsAuthenticated == true)
        {
            _logger.LogInformation("KeycloakXafBridgeMiddleware: User is authenticated, identity type: {IdentityType}", 
                context.User.Identity.GetType().Name);
            _logger.LogInformation("KeycloakXafBridgeMiddleware: Authentication type: {AuthType}", 
                context.User.Identity.AuthenticationType);
            _logger.LogInformation("KeycloakXafBridgeMiddleware: User name: {UserName}", 
                context.User.Identity.Name);

            // Log all claims for debugging
            if (context.User is ClaimsPrincipal claimsPrincipal)
            {
                foreach (var claim in claimsPrincipal.Claims)
                {
                    _logger.LogInformation("KeycloakXafBridgeMiddleware: Claim - Type: {Type}, Value: {Value}", 
                        claim.Type, claim.Value);
                }
            }

            // Check if this is a Keycloak authentication that needs to be bridged to XAF
            bool isKeycloakAuth = IsKeycloakAuthentication(context.User);
            bool isXafAuth = context.User.Identity.AuthenticationType == SecurityDefaults.Issuer;

            _logger.LogInformation("IsKeycloakAuthentication - AuthType: {AuthType}, IsKeycloakAuthType: {IsKeycloakAuthType}, HasKeycloakClaims: {HasKeycloakClaims}", 
                context.User.Identity.AuthenticationType,
                context.User.Identity.AuthenticationType == "Keycloak" || context.User.Identity.AuthenticationType == "OpenIdConnect",
                HasKeycloakClaims(context.User));

            if (isKeycloakAuth && !isXafAuth)
            {
                _logger.LogInformation("KeycloakXafBridgeMiddleware: Bridging Keycloak authentication to XAF");
                
                // Create XAF security claims based on Keycloak authentication
                var identity = new ClaimsIdentity(SecurityDefaults.Issuer);
                
                // Copy essential claims from Keycloak to XAF identity
                var claimsToTransfer = new[]
                {
                    ClaimTypes.NameIdentifier,
                    ClaimTypes.Name,
                    ClaimTypes.Email,
                    ClaimTypes.GivenName,
                    ClaimTypes.Surname,
                    "sub",
                    "preferred_username",
                    "email",
                    "given_name",
                    "family_name"
                };

                foreach (var claimType in claimsToTransfer)
                {
                    var claim = context.User.FindFirst(claimType);
                    if (claim != null)
                    {
                        identity.AddClaim(new Claim(claimType, claim.Value, claim.ValueType, SecurityDefaults.Issuer));
                    }
                }

                // Add XAF-specific claims
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, 
                    context.User.FindFirst("sub")?.Value ?? context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "", 
                    ClaimValueTypes.String, SecurityDefaults.Issuer));

                // Replace the current user with XAF-compatible principal
                context.User = new ClaimsPrincipal(identity);
                
                _logger.LogInformation("KeycloakXafBridgeMiddleware: Successfully bridged to XAF authentication");
            }
            else if (isKeycloakAuth && isXafAuth)
            {
                _logger.LogInformation("KeycloakXafBridgeMiddleware: User already has XAF authentication");
            }
            else if (!isKeycloakAuth && isXafAuth)
            {
                _logger.LogInformation("KeycloakXafBridgeMiddleware: Skipping bridge - IsKeycloak: {IsKeycloak}, IsXafAuth: {IsXafAuth}", 
                    isKeycloakAuth, isXafAuth);
            }
            else
            {
                _logger.LogInformation("KeycloakXafBridgeMiddleware: Authentication type not handled: {AuthType}", 
                    context.User.Identity.AuthenticationType);
            }
        }
        else
        {
            _logger.LogInformation("KeycloakXafBridgeMiddleware: User is not authenticated");
        }

        await _next(context);
    }

    private bool IsLogoutPath(PathString path)
    {
        var logoutPaths = new[]
        {
            "/Authentication/Logout",
            "/signout-oidc",
            "/signout-callback-oidc",
            "/ExternalAuth/Logout"
        };

        return logoutPaths.Any(logoutPath => 
            path.Value?.StartsWith(logoutPath, StringComparison.OrdinalIgnoreCase) == true);
    }

    private bool IsKeycloakAuthentication(ClaimsPrincipal user)
    {
        // Check authentication type
        bool isKeycloakAuthType = user.Identity.AuthenticationType == "Keycloak" || 
                                 user.Identity.AuthenticationType == "OpenIdConnect";
        
        // Check for Keycloak-specific claims
        bool hasKeycloakClaims = HasKeycloakClaims(user);
        
        return isKeycloakAuthType || hasKeycloakClaims;
    }

    private bool HasKeycloakClaims(ClaimsPrincipal user)
    {
        // Check for Keycloak-specific claims that indicate this is a Keycloak authentication
        var keycloakClaims = new[] { "iss", "aud", "typ", "azp", "session_state", "preferred_username" };
        return keycloakClaims.Any(claim => user.HasClaim(claim, c => !string.IsNullOrEmpty(c)));
    }
}
```

### 3. Create External Authentication Controller

Create `Controllers/ExternalAuthController.cs`:

```csharp
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace XafKeycloakAuth.Blazor.Server.Controllers;

/// <summary>
/// Controller to handle external authentication challenges.
/// This allows users to choose between password and external authentication methods.
/// </summary>
[Route("[controller]")]
public class ExternalAuthController : Controller
{
    /// <summary>
    /// Initiates Keycloak authentication challenge
    /// </summary>
    /// <param name="returnUrl">URL to return to after authentication</param>
    /// <returns>Challenge result that redirects to Keycloak</returns>
    [HttpGet("Keycloak")]
    public IActionResult LoginWithKeycloak(string returnUrl = "/")
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = returnUrl
        };
        
        return Challenge(properties, "Keycloak");
    }
    
    /// <summary>
    /// Handles logout for external authentication
    /// </summary>
    /// <returns>SignOut result for both local and external authentication</returns>
    [HttpPost("Logout")]
    public IActionResult ExternalLogout()
    {
        // Sign out from both the local authentication scheme and Keycloak
        return SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            "Cookies", // Local authentication scheme
            "Keycloak"  // External authentication scheme
        );
    }
}
```

### 4. Create Enhanced Authentication Controller

Create `API/Security/AuthenticationController.cs`:

```csharp
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using DevExpress.ExpressApp.Security;
using System.Reflection;

namespace XafKeycloakAuth.Blazor.Server.API.Security;

/// <summary>
/// Enhanced authentication controller with comprehensive logout support.
/// Handles both XAF internal logout and external authentication provider logout.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly ILogger<AuthenticationController> _logger;

    public AuthenticationController(ILogger<AuthenticationController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Comprehensive logout endpoint that clears authentication state from both XAF and Keycloak
    /// </summary>
    [HttpPost("Logout")]
    public async Task<IActionResult> Logout()
    {
        _logger.LogInformation("=== Starting comprehensive logout process ===");
        
        try
        {
            // Step 1: XAF SignInManager logout using reflection (for internal XAF state)
            await LogoutFromXafSignInManager();
            
            // Step 2: ASP.NET Core authentication logout (clears cookies and local session)
            await HttpContext.SignOutAsync();
            _logger.LogInformation("✓ ASP.NET Core authentication logout completed");
            
            // Step 3: External authentication logout (Keycloak)
            var keycloakLogoutUrl = await GetKeycloakLogoutUrl();
            
            if (!string.IsNullOrEmpty(keycloakLogoutUrl))
            {
                _logger.LogInformation("✓ Redirecting to Keycloak logout: {LogoutUrl}", keycloakLogoutUrl);
                
                // Return redirect to Keycloak logout
                return new JsonResult(new { 
                    success = true, 
                    redirectUrl = keycloakLogoutUrl,
                    message = "Logout successful, redirecting to Keycloak logout" 
                });
            }
            else
            {
                _logger.LogInformation("✓ Local logout completed successfully");
                return new JsonResult(new { 
                    success = true, 
                    redirectUrl = "/",
                    message = "Logout successful" 
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Error during logout process");
            return new JsonResult(new { 
                success = false, 
                error = ex.Message 
            }) { StatusCode = 500 };
        }
    }

    private async Task LogoutFromXafSignInManager()
    {
        try
        {
            // Use reflection to access DevExpress SignInManager
            var signInManagerType = Type.GetType("Microsoft.AspNetCore.Identity.SignInManager`1[[DevExpress.Persistent.BaseImpl.EF.PermissionPolicy.PermissionPolicyUser, DevExpress.Persistent.BaseImpl.EFCore]], Microsoft.AspNetCore.Identity");
            
            if (signInManagerType != null)
            {
                var signInManager = HttpContext.RequestServices.GetService(signInManagerType);
                if (signInManager != null)
                {
                    var signOutMethod = signInManagerType.GetMethod("SignOutAsync", BindingFlags.Public | BindingFlags.Instance);
                    if (signOutMethod != null)
                    {
                        var task = (Task)signOutMethod.Invoke(signInManager, null);
                        await task;
                        _logger.LogInformation("✓ XAF SignInManager logout completed");
                    }
                    else
                    {
                        _logger.LogWarning("⚠ SignOutAsync method not found on SignInManager");
                    }
                }
                else
                {
                    _logger.LogWarning("⚠ SignInManager service not found");
                }
            }
            else
            {
                _logger.LogWarning("⚠ SignInManager type not found");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Error during XAF SignInManager logout");
            // Don't throw - continue with other logout steps
        }
    }

    private async Task<string> GetKeycloakLogoutUrl()
    {
        try
        {
            // Check if user was authenticated via Keycloak
            if (User?.Identity?.IsAuthenticated == true)
            {
                var authType = User.Identity.AuthenticationType;
                _logger.LogInformation("Current authentication type: {AuthType}", authType);
                
                // Build Keycloak logout URL
                var authority = "http://localhost:8080/realms/xaf-realm"; // From configuration
                var clientId = "xaf-blazor-app"; // From configuration
                var postLogoutRedirectUri = "https://localhost:5001/";
                
                var logoutUrl = $"{authority}/protocol/openid-connect/logout" +
                               $"?client_id={Uri.EscapeDataString(clientId)}" +
                               $"&post_logout_redirect_uri={Uri.EscapeDataString(postLogoutRedirectUri)}";
                
                return logoutUrl;
            }
            
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Error getting Keycloak logout URL");
            return null;
        }
    }
}
```

### 5. Update Startup.cs Configuration

Update your `Startup.cs` file:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    // ... existing services ...

    services.AddXaf(Configuration, builder => {
        // ... existing XAF configuration ...
        
        builder.Security
            .UseIntegratedMode(options => {
                // ... existing security options ...
            })
            // CRITICAL: Add both authentication methods for proper logout behavior
            .AddPasswordAuthentication(options => {
                options.IsSupportChangePassword = true;
            })
            .AddAuthenticationProvider<KeycloakAuthenticationProvider>();
    });
    
    // CRITICAL: Don't set DefaultChallengeScheme to prevent automatic OAuth redirect
    var authentication = services.AddAuthentication(options => {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        // Allow users to choose between password and external authentication
        // Don't set a default challenge scheme to prevent automatic OAuth redirect
    });
    
    authentication.AddCookie(options => {
        options.LoginPath = "/LoginPage";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
        options.SlidingExpiration = true;
        options.Cookie.SameSite = SameSiteMode.None;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.Cookie.HttpOnly = true;
    });
    
    // Add Keycloak OpenID Connect authentication
    authentication.AddOpenIdConnect("Keycloak", "Keycloak", options => {
        var keycloakConfig = Configuration.GetSection("Authentication:Keycloak");
        
        options.Authority = keycloakConfig["Authority"];
        options.ClientId = keycloakConfig["ClientId"];
        options.ClientSecret = keycloakConfig["ClientSecret"];
        options.RequireHttpsMetadata = bool.Parse(keycloakConfig["RequireHttpsMetadata"] ?? "false");
        options.ResponseType = keycloakConfig["ResponseType"];
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.CallbackPath = keycloakConfig["CallbackPath"];
        options.SignedOutCallbackPath = keycloakConfig["SignedOutCallbackPath"];
        options.GetClaimsFromUserInfoEndpoint = bool.Parse(keycloakConfig["GetClaimsFromUserInfoEndpoint"] ?? "true");
        options.SaveTokens = bool.Parse(keycloakConfig["SaveTokens"] ?? "true");
        options.UsePkce = bool.Parse(keycloakConfig["UsePkce"] ?? "false");
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        
        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                logger.LogInformation("Redirecting to Keycloak for logout");
                return Task.CompletedTask;
            },
            OnSignedOutCallbackRedirect = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                logger.LogInformation("Keycloak logout completed, redirecting to home");
                context.Response.Redirect("/");
                context.HandleResponse();
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                logger.LogError(context.Exception, "Keycloak authentication failed");
                return Task.CompletedTask;
            }
        };
    });
    
    // ... rest of configuration ...
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // ... existing middleware ...
    
    app.UseAuthentication();
    app.UseAuthorization();
    app.UseXaf();
    
    // CRITICAL: Add bridge middleware AFTER XAF initialization
    app.UseMiddleware<KeycloakXafBridgeMiddleware>();
    
    // ... rest of pipeline ...
}
```

## Logout Configuration

The logout configuration is automatically handled by the implementation above. Key points:

1. **Multiple Authentication Methods**: Both password and Keycloak authentication are configured, which disables XAF's automatic re-authentication behavior.

2. **No Default Challenge Scheme**: By not setting `DefaultChallengeScheme`, users can choose their authentication method.

3. **Comprehensive Logout**: The `AuthenticationController` handles three-layer logout:
   - XAF SignInManager logout
   - ASP.NET Core authentication logout  
   - Keycloak external logout

4. **Bridge Middleware**: Properly bridges Keycloak authentication to XAF while respecting logout paths.

## Testing

### 1. Start Your Application

```bash
cd YourProject.Blazor.Server
dotnet run
```

### 2. Test Authentication Flows

1. **Password Authentication**: 
   - Navigate to `https://localhost:5001`
   - Use XAF login form with username/password

2. **Keycloak Authentication**:
   - Navigate to `https://localhost:5001/ExternalAuth/Keycloak`
   - Login with Keycloak credentials (testuser / Test123!)

3. **Logout Testing**:
   - Login with either method
   - Use logout functionality
   - Verify user stays logged out (no automatic re-authentication)
   - Check that service-worker.js shows "User is not authenticated"

### 3. Test User Creation

When a user logs in via Keycloak for the first time:
- A new `ApplicationUser` is automatically created
- User is assigned to "Default" role
- Login info is stored for future authentications

## Troubleshooting

### Common Issues

1. **Automatic Re-authentication After Logout**
   - Ensure both `AddPasswordAuthentication()` and `AddAuthenticationProvider<KeycloakAuthenticationProvider>()` are configured
   - Verify `DefaultChallengeScheme` is NOT set in authentication options

2. **Keycloak Connection Issues**
   - Check Keycloak is running: `docker ps`
   - Verify realm and client configuration
   - Check `RequireHttpsMetadata` is set to `false` for development

3. **Claims Mapping Issues**
   - Review logs for claim information
   - Verify Keycloak client mappers are configured
   - Check `KeycloakAuthenticationProvider.CreateApplicationUser()` method

4. **Logout Not Working**
   - Verify middleware order in `Configure()` method
   - Check logout paths in `KeycloakXafBridgeMiddleware.IsLogoutPath()`
   - Review `AuthenticationController.Logout()` logs

### Logging

Enable detailed logging in `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "XafKeycloakAuth.Blazor.Server.Services": "Information",
      "Microsoft.AspNetCore.Authentication": "Information"
    }
  }
}
```

### Keycloak Admin Console

Access the Keycloak admin console at `http://localhost:8080/admin` to:
- Manage users and roles
- Review authentication events
- Configure additional client settings
- Monitor login attempts

## Advanced Configuration

### Custom User Properties

To map additional Keycloak claims to user properties:

1. Add properties to your `ApplicationUser` class
2. Update the `SetPropertyIfExists()` calls in `KeycloakAuthenticationProvider`
3. Configure corresponding protocol mappers in Keycloak

### Role Mapping

To map Keycloak roles to XAF roles:

1. Configure role mappers in Keycloak client
2. Update `CreateApplicationUser()` to read role claims
3. Map roles to existing XAF `PermissionPolicyRole` objects

### Production Configuration

For production deployment:
- Set `RequireHttpsMetadata` to `true`
- Use proper SSL certificates
- Configure secure client secrets
- Update redirect URIs for production domains
- Enable proper logging and monitoring

## Security Considerations

1. **Client Secret**: Store securely using Azure Key Vault or similar
2. **Token Validation**: Ensure proper token validation in production
3. **HTTPS**: Always use HTTPS in production
4. **Session Management**: Configure appropriate session timeouts
5. **User Data**: Implement proper data protection for user information

---

This guide provides a complete implementation of Keycloak authentication with XAF, including the critical logout fix that prevents automatic re-authentication. The solution ensures users can choose between password and external authentication while maintaining proper security boundaries.