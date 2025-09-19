using System.Security.Claims;
using DevExpress.ExpressApp;
using DevExpress.ExpressApp.Security;
using DevExpress.ExpressApp.Security.Authentication;
using DevExpress.ExpressApp.Security.Authentication.ClientServer;
using DevExpress.Data.Filtering;
using DevExpress.Persistent.BaseImpl.EF.PermissionPolicy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using XafKeycloakAuth.Module.BusinessObjects;
using DevExpress.ExpressApp.Blazor;
using DevExpress.ExpressApp.Blazor.Services;

namespace XafKeycloakAuth.Blazor.Server.Services;

/// <summary>
/// Middleware to bridge ASP.NET Core Keycloak authentication with XAF Security System.
/// This handles the two-stage authentication process required by XAF:
/// 1. ASP.NET Core authenticates user with Keycloak
/// 2. This middleware bridges to XAF's internal security system
/// 
/// Based on DevExpress support ticket T1097193 and requirements analysis.
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
        
        // Skip processing for logout-related paths to prevent automatic re-authentication during logout
        if (IsLogoutPath(context.Request.Path))
        {
            _logger.LogInformation("KeycloakXafBridgeMiddleware: Skipping processing for logout path: {Path}", context.Request.Path);
            await _next(context);
            return;
        }
        
        // Only process if user is authenticated via Keycloak but not yet authenticated in XAF
        if (context.User.Identity.IsAuthenticated)
        {
            _logger.LogInformation("KeycloakXafBridgeMiddleware: User is authenticated, identity type: {IdentityType}", context.User.Identity.GetType().Name);
            _logger.LogInformation("KeycloakXafBridgeMiddleware: Authentication type: {AuthType}", context.User.Identity.AuthenticationType);
            _logger.LogInformation("KeycloakXafBridgeMiddleware: User name: {UserName}", context.User.Identity.Name);
            
            // Log all claims for debugging
            foreach (var claim in context.User.Claims)
            {
                _logger.LogInformation("KeycloakXafBridgeMiddleware: Claim - Type: {Type}, Value: {Value}", claim.Type, claim.Value);
            }
            
            if (IsKeycloakAuthentication(context.User) && !IsXafAuthenticated(context.User))
            {
                _logger.LogInformation("KeycloakXafBridgeMiddleware: Processing Keycloak to XAF bridge");
                await ProcessKeycloakToXafBridge(context);
            }
            else
            {
                _logger.LogInformation("KeycloakXafBridgeMiddleware: Skipping bridge - IsKeycloak: {IsKeycloak}, IsXafAuth: {IsXafAuth}", 
                    IsKeycloakAuthentication(context.User), IsXafAuthenticated(context.User));
            }
        }
        else
        {
            _logger.LogInformation("KeycloakXafBridgeMiddleware: User is not authenticated");
        }

        await _next(context);
    }

    private bool IsKeycloakAuthentication(ClaimsPrincipal user)
    {
        var authType = user.Identity.AuthenticationType;
        
        // Check for Keycloak-specific authentication types and claims
        var isKeycloakAuthType = authType == "Keycloak" || 
                                authType == "OpenIdConnect" || 
                                authType == "oidc" ||
                                authType == "AuthenticationTypes.Federation";
        
        // Also check for Keycloak-specific claims as a backup
        var hasKeycloakClaims = user.HasClaim(c => c.Type == "preferred_username") || 
                               user.HasClaim(c => c.Type == "iss" && c.Value.Contains("keycloak"));
        
        _logger.LogInformation("IsKeycloakAuthentication - AuthType: {AuthType}, IsKeycloakAuthType: {IsKeycloakAuthType}, HasKeycloakClaims: {HasKeycloakClaims}", 
            authType, isKeycloakAuthType, hasKeycloakClaims);
            
        return isKeycloakAuthType || hasKeycloakClaims;
    }

    private bool IsXafAuthenticated(ClaimsPrincipal user)
    {
        // Check if user has XAF-specific authentication
        // XAF uses SecurityDefaults.Issuer as the authentication type for its internal authentication
        return user.Identity?.AuthenticationType == SecurityDefaults.Issuer ||
               user.HasClaim(c => c.Issuer == SecurityDefaults.Issuer);
    }

    private bool IsLogoutPath(string path)
    {
        // Define paths that should be excluded from automatic authentication processing
        // to prevent re-authentication during logout flows
        var logoutPaths = new[]
        {
            "/Authentication/Logout",
            "/Authentication/LogoutCallback", 
            "/signin-oidc",
            "/signout-oidc",
            "/signout-callback-oidc",
            "/Account/Logout",
            "/api/Authentication/Logout",
            "/api/Authentication/LogoutCallback"
        };
        
        return logoutPaths.Any(logoutPath => 
            path.ToString().StartsWith(logoutPath, StringComparison.OrdinalIgnoreCase));
    }

    private async Task ProcessKeycloakToXafBridge(HttpContext context)
    {
        try
        {
            _logger.LogInformation("Processing Keycloak to XAF authentication bridge for user: {UserName}", 
                context.User.Identity.Name);

            // Extract user information from Keycloak claims
            var userInfo = ExtractUserInfoFromClaims(context.User);
            if (userInfo == null)
            {
                _logger.LogWarning("Could not extract user information from Keycloak claims");
                return;
            }

            // Get the SignInManager service (following XafBypassLogin example)
            var signInManager = context.RequestServices.GetRequiredService<SignInManager>();

            // First, ensure the user exists in XAF (check/create before authentication attempt)
            await TryCreateXafUser(context, userInfo);

            // Now try to sign in with empty password (like the bypass login example)
            // For Keycloak users, we don't have their password, so we use empty string
            var authResult = signInManager.SignInByPassword(userInfo.Username, "");
            
            if (authResult.Succeeded)
            {
                _logger.LogInformation("Successfully signed in user {Username} to XAF", userInfo.Username);
                
                // CRITICAL: Replace the current user context with the XAF authenticated principal
                // This ensures XAF recognizes the user as properly authenticated
                context.User = authResult.Principal;
                
                // Establish persistent authentication cookie (following XafBypassLogin example)
                await context.SignInAsync(authResult.Principal);
                
                // Store additional Keycloak claims in the context for potential use
                context.Items["KeycloakClaims"] = context.User.Claims.ToList();
                
                _logger.LogInformation("XAF authentication cookie established for user: {Username}. Principal name: {PrincipalName}", 
                    userInfo.Username, authResult.Principal?.Identity?.Name);
            }
            else
            {
                _logger.LogError("XAF authentication failed for user: {Username} even after ensuring user exists in database", userInfo.Username);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during Keycloak to XAF authentication bridge");
        }
    }

    /// <summary>
    /// Try to create a new XAF user based on Keycloak user information
    /// </summary>
    private Task<bool> TryCreateXafUser(HttpContext context, KeycloakUserInfo userInfo)
    {
        try
        {
            _logger.LogInformation("Checking if XAF user exists: {Username}", userInfo.Username);
            
            // Use INonSecuredObjectSpaceFactory to create users (following Updater.cs pattern)
            var objectSpaceFactory = context.RequestServices.GetRequiredService<INonSecuredObjectSpaceFactory>();
            using var objectSpace = objectSpaceFactory.CreateNonSecuredObjectSpace(typeof(ApplicationUser));

            // Get UserManager service (following Updater.cs pattern)
            var userManager = context.RequestServices.GetRequiredService<UserManager>();
            
            // Check if user already exists (prevent duplicate creation)
            var existingUser = userManager.FindUserByName<ApplicationUser>(objectSpace, userInfo.Username);
            if (existingUser != null)
            {
                _logger.LogInformation("XAF user already exists: {Username}", userInfo.Username);
                return Task.FromResult(true);
            }

            _logger.LogInformation("Creating new XAF user: {Username}", userInfo.Username);
            
            // Find or create admin role (following Updater.cs pattern)
            var adminRole = objectSpace.FirstOrDefault<PermissionPolicyRole>(r => r.Name == "Administrators");
            if (adminRole == null)
            {
                adminRole = objectSpace.CreateObject<PermissionPolicyRole>();
                adminRole.Name = "Administrators";
                adminRole.IsAdministrative = true;
                _logger.LogInformation("Created Administrators role");
            }

            // Create new user using UserManager (following Updater.cs pattern)
            string emptyPassword = ""; // For Keycloak users, we use empty password like in Updater.cs
            var newUser = userManager.CreateUser<ApplicationUser>(objectSpace, userInfo.Username, emptyPassword, (user) => {
                // Add the Administrators role to the user (like Admin user in Updater.cs)
                user.Roles.Add(adminRole);
                
                // Mark this user as created by Keycloak
                user.CreatedByKeycloak = true;
                
                _logger.LogInformation("Assigned Administrators role to user: {Username}", userInfo.Username);
                _logger.LogInformation("Marked user as created by Keycloak: {Username}", userInfo.Username);
            });
            
            // Save changes
            objectSpace.CommitChanges();
            
            _logger.LogInformation("Successfully created XAF user with admin role: {Username}", userInfo.Username);
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating XAF user for: {Username}", userInfo.Username);
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Extracts user information from Keycloak claims
    /// </summary>
    private KeycloakUserInfo ExtractUserInfoFromClaims(ClaimsPrincipal principal)
    {
        var username = principal.FindFirst("preferred_username")?.Value 
                      ?? principal.FindFirst(ClaimTypes.Name)?.Value
                      ?? principal.FindFirst("sub")?.Value;

        if (string.IsNullOrEmpty(username))
        {
            return null;
        }

        return new KeycloakUserInfo
        {
            Username = username,
            Email = principal.FindFirst("email")?.Value ?? principal.FindFirst(ClaimTypes.Email)?.Value,
            FirstName = principal.FindFirst("given_name")?.Value ?? principal.FindFirst(ClaimTypes.GivenName)?.Value,
            LastName = principal.FindFirst("family_name")?.Value ?? principal.FindFirst(ClaimTypes.Surname)?.Value,
            DisplayName = principal.FindFirst("name")?.Value ?? principal.FindFirst(ClaimTypes.Name)?.Value
        };
    }
}

/// <summary>
/// Helper class to hold Keycloak user information
/// </summary>
public class KeycloakUserInfo
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string DisplayName { get; set; }
}