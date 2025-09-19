using System.Security.Claims;
using DevExpress.ExpressApp.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xaf.Blazor.KeycloakAuth.Configuration;

namespace Xaf.Blazor.KeycloakAuth.Middleware;

/// <summary>
/// Middleware to bridge Keycloak authentication with XAF Security System.
/// This ensures that authenticated Keycloak users are properly recognized by XAF.
/// </summary>
public class KeycloakXafBridgeMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<KeycloakXafBridgeMiddleware> _logger;
    private readonly XafKeycloakOptions _options;

    public KeycloakXafBridgeMiddleware(
        RequestDelegate next,
        ILogger<KeycloakXafBridgeMiddleware> logger,
        IOptions<XafKeycloakOptions> options)
    {
        _next = next;
        _logger = logger;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        _logger.LogDebug("KeycloakXafBridgeMiddleware: Processing request for path: {Path}", context.Request.Path);

        // Skip processing for logout paths to prevent interference with logout process
        if (IsLogoutPath(context.Request.Path))
        {
            _logger.LogDebug("KeycloakXafBridgeMiddleware: Skipping logout path: {Path}", context.Request.Path);
            await _next(context);
            return;
        }

        if (context.User?.Identity?.IsAuthenticated == true)
        {
            LogAuthenticationDetails(context);

            // Check if this is a Keycloak authentication that needs to be bridged to XAF
            bool isKeycloakAuth = IsKeycloakAuthentication(context.User);
            bool isXafAuth = context.User.Identity.AuthenticationType == SecurityDefaults.Issuer;

            _logger.LogDebug("Authentication analysis - IsKeycloak: {IsKeycloak}, IsXafAuth: {IsXafAuth}, AuthType: {AuthType}",
                isKeycloakAuth, isXafAuth, context.User.Identity.AuthenticationType);

            if (isKeycloakAuth && !isXafAuth)
            {
                await BridgeKeycloakToXafAuthentication(context);
            }
            else if (isKeycloakAuth && isXafAuth)
            {
                _logger.LogDebug("KeycloakXafBridgeMiddleware: User already has XAF authentication");
            }
            else if (!isKeycloakAuth && isXafAuth)
            {
                _logger.LogDebug("KeycloakXafBridgeMiddleware: Skipping bridge - pure XAF authentication");
            }
            else
            {
                _logger.LogDebug("KeycloakXafBridgeMiddleware: Authentication type not handled: {AuthType}", 
                    context.User.Identity.AuthenticationType);
            }
        }
        else
        {
            _logger.LogDebug("KeycloakXafBridgeMiddleware: User is not authenticated");
        }

        await _next(context);
    }

    /// <summary>
    /// Bridges Keycloak authentication to XAF-compatible authentication
    /// </summary>
    private async Task BridgeKeycloakToXafAuthentication(HttpContext context)
    {
        _logger.LogInformation("KeycloakXafBridgeMiddleware: Bridging Keycloak authentication to XAF");
        
        try
        {
            // Create XAF security claims based on Keycloak authentication
            var identity = new ClaimsIdentity(SecurityDefaults.Issuer);
            
            // Copy essential claims from Keycloak to XAF identity
            var claimsToTransfer = GetClaimsToTransfer();
            
            foreach (var claimType in claimsToTransfer)
            {
                var claim = context.User.FindFirst(claimType);
                if (claim != null)
                {
                    identity.AddClaim(new Claim(claimType, claim.Value, claim.ValueType, SecurityDefaults.Issuer));
                }
            }

            // Ensure we have a valid user identifier for XAF
            var userIdClaim = context.User.FindFirst("sub") ?? context.User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim != null)
            {
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userIdClaim.Value, ClaimValueTypes.String, SecurityDefaults.Issuer));
            }

            // Replace the current user with XAF-compatible principal
            context.User = new ClaimsPrincipal(identity);
            
            _logger.LogInformation("KeycloakXafBridgeMiddleware: Successfully bridged to XAF authentication");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "KeycloakXafBridgeMiddleware: Error during authentication bridge");
            // Don't throw - allow request to continue
        }
    }

    /// <summary>
    /// Gets the list of claims to transfer from Keycloak to XAF
    /// </summary>
    private static string[] GetClaimsToTransfer()
    {
        return new[]
        {
            ClaimTypes.NameIdentifier,
            ClaimTypes.Name,
            ClaimTypes.Email,
            ClaimTypes.GivenName,
            ClaimTypes.Surname,
            ClaimTypes.Role,
            "sub",
            "preferred_username",
            "email",
            "given_name",
            "family_name",
            "name",
            "roles",
            "realm_access",
            "resource_access"
        };
    }

    /// <summary>
    /// Logs authentication details for debugging
    /// </summary>
    private void LogAuthenticationDetails(HttpContext context)
    {
        if (!_logger.IsEnabled(LogLevel.Debug)) return;

        _logger.LogDebug("KeycloakXafBridgeMiddleware: User is authenticated, identity type: {IdentityType}", 
            context.User.Identity?.GetType().Name);
        _logger.LogDebug("KeycloakXafBridgeMiddleware: Authentication type: {AuthType}", 
            context.User.Identity?.AuthenticationType);
        _logger.LogDebug("KeycloakXafBridgeMiddleware: User name: {UserName}", 
            context.User.Identity?.Name);

        // Log claims in debug mode
        if (context.User is ClaimsPrincipal claimsPrincipal)
        {
            foreach (var claim in claimsPrincipal.Claims.Take(10)) // Limit to first 10 claims to avoid log spam
            {
                _logger.LogDebug("KeycloakXafBridgeMiddleware: Claim - Type: {Type}, Value: {Value}", 
                    claim.Type, claim.Value.Length > 100 ? claim.Value[..100] + "..." : claim.Value);
            }
        }
    }

    /// <summary>
    /// Determines if the current path is a logout path that should be skipped
    /// </summary>
    private bool IsLogoutPath(PathString path)
    {
        var logoutPaths = new List<string>
        {
            _options.Logout.LogoutEndpoint,
            _options.Logout.ExternalAuthLogoutEndpoint,
            "/signout-oidc",
            "/signout-callback-oidc",
            _options.Server.SignedOutCallbackPath
        };

        // Add any custom logout paths from configuration
        // This could be extended to be configurable

        return logoutPaths.Any(logoutPath => 
            path.Value?.StartsWith(logoutPath, StringComparison.OrdinalIgnoreCase) == true);
    }

    /// <summary>
    /// Determines if the current user was authenticated via Keycloak
    /// </summary>
    private bool IsKeycloakAuthentication(ClaimsPrincipal user)
    {
        var authType = user.Identity?.AuthenticationType;
        
        // Check authentication type matches our Keycloak scheme
        bool isKeycloakAuthType = authType == _options.Authentication.SchemeName ||
                                 authType == "OpenIdConnect" ||
                                 authType == "Keycloak";
        
        // Check for Keycloak-specific claims as additional verification
        bool hasKeycloakClaims = HasKeycloakClaims(user);
        
        var result = isKeycloakAuthType || hasKeycloakClaims;
        
        _logger.LogDebug("IsKeycloakAuthentication - AuthType: {AuthType}, IsKeycloakAuthType: {IsKeycloakAuthType}, HasKeycloakClaims: {HasKeycloakClaims}, Result: {Result}", 
            authType, isKeycloakAuthType, hasKeycloakClaims, result);
        
        return result;
    }

    /// <summary>
    /// Checks if the principal has Keycloak-specific claims
    /// </summary>
    private static bool HasKeycloakClaims(ClaimsPrincipal user)
    {
        // Check for Keycloak-specific claims that indicate this is a Keycloak authentication
        var keycloakClaims = new[] { "iss", "aud", "typ", "azp", "session_state", "preferred_username" };
        return keycloakClaims.Any(claimType => user.Claims.Any(c => c.Type == claimType && !string.IsNullOrEmpty(c.Value)));
    }
}

/// <summary>
/// Extension methods for adding the Keycloak XAF bridge middleware
/// </summary>
public static class KeycloakXafBridgeMiddlewareExtensions
{
    /// <summary>
    /// Adds the Keycloak XAF bridge middleware to the application pipeline.
    /// This should be called after UseXaf() but before any XAF-specific middleware.
    /// </summary>
    /// <param name="builder">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseKeycloakXafBridge(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<KeycloakXafBridgeMiddleware>();
    }
}