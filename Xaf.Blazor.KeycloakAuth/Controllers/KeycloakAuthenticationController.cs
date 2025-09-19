using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Reflection;
using Xaf.Blazor.KeycloakAuth.Configuration;

namespace Xaf.Blazor.KeycloakAuth.Controllers;

/// <summary>
/// Enhanced authentication controller with comprehensive logout support for Keycloak integration.
/// Handles both XAF internal logout and external authentication provider logout.
/// </summary>
[ApiController]
public class KeycloakAuthenticationController : ControllerBase
{
    private readonly ILogger<KeycloakAuthenticationController> _logger;
    private readonly XafKeycloakOptions _options;

    public KeycloakAuthenticationController(
        ILogger<KeycloakAuthenticationController> logger,
        IOptions<XafKeycloakOptions> options)
    {
        _logger = logger;
        _options = options.Value;
    }

    /// <summary>
    /// Comprehensive logout endpoint that clears authentication state from both XAF and Keycloak
    /// </summary>
    [HttpPost("Logout")]
    public async Task<IActionResult> Logout()
    {
        _logger.LogInformation("=== Starting comprehensive logout process ===");
        
        if (!_options.Logout.EnableComprehensiveLogout)
        {
            _logger.LogInformation("Comprehensive logout is disabled in configuration");
            return Ok(new { success = true, message = "Logout feature is disabled" });
        }

        try
        {
            // Step 1: XAF SignInManager logout using reflection (for internal XAF state)
            if (_options.Logout.EnableXafSignInManagerLogout)
            {
                await LogoutFromXafSignInManager();
            }
            
            // Step 2: ASP.NET Core authentication logout (clears cookies and local session)
            await HttpContext.SignOutAsync();
            _logger.LogInformation("✓ ASP.NET Core authentication logout completed");
            
            // Step 3: External authentication logout (Keycloak)
            var keycloakLogoutUrl = await GetKeycloakLogoutUrl();
            
            if (!string.IsNullOrEmpty(keycloakLogoutUrl))
            {
                _logger.LogInformation("✓ Redirecting to Keycloak logout: {LogoutUrl}", keycloakLogoutUrl);
                
                // Return redirect to Keycloak logout
                return Ok(new { 
                    success = true, 
                    redirectUrl = keycloakLogoutUrl,
                    message = "Logout successful, redirecting to Keycloak logout" 
                });
            }
            else
            {
                _logger.LogInformation("✓ Local logout completed successfully");
                return Ok(new { 
                    success = true, 
                    redirectUrl = _options.Logout.PostLogoutRedirectUrl,
                    message = "Logout successful" 
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Error during logout process");
            return StatusCode(500, new { 
                success = false, 
                error = ex.Message 
            });
        }
    }

    /// <summary>
    /// Initiates Keycloak authentication challenge
    /// </summary>
    /// <param name="returnUrl">URL to return to after authentication</param>
    /// <returns>Challenge result that redirects to Keycloak</returns>
    [HttpGet("Login/Keycloak")]
    public IActionResult LoginWithKeycloak(string returnUrl = "/")
    {
        _logger.LogInformation("Initiating Keycloak authentication challenge");
        
        var properties = new AuthenticationProperties
        {
            RedirectUri = returnUrl
        };
        
        return Challenge(properties, _options.Authentication.SchemeName);
    }

    /// <summary>
    /// External authentication logout endpoint
    /// </summary>
    [HttpPost("Logout/External")]
    public IActionResult ExternalLogout()
    {
        if (!_options.Logout.EnableExternalAuthLogout)
        {
            _logger.LogWarning("External authentication logout is disabled in configuration");
            return BadRequest(new { error = "External logout is disabled" });
        }

        _logger.LogInformation("Initiating external authentication logout");
        
        // Sign out from both the local authentication scheme and Keycloak
        return SignOut(
            new AuthenticationProperties { RedirectUri = _options.Logout.PostLogoutRedirectUrl },
            "Cookies", // Local authentication scheme
            _options.Authentication.SchemeName  // External authentication scheme
        );
    }

    /// <summary>
    /// Logs out from XAF SignInManager using reflection to access internal XAF state
    /// </summary>
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
                        var task = (Task)signOutMethod.Invoke(signInManager, null)!;
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

    /// <summary>
    /// Builds the Keycloak logout URL based on configuration
    /// </summary>
    private async Task<string?> GetKeycloakLogoutUrl()
    {
        try
        {
            // Check if user was authenticated via Keycloak
            if (User?.Identity?.IsAuthenticated == true)
            {
                var authType = User.Identity.AuthenticationType;
                _logger.LogInformation("Current authentication type: {AuthType}", authType);
                
                // Only build Keycloak logout URL if user was authenticated via Keycloak
                if (authType == _options.Authentication.SchemeName || 
                    authType == "OpenIdConnect" || 
                    authType == "Keycloak")
                {
                    var authority = _options.Server.Authority;
                    var clientId = _options.Server.ClientId;
                    var postLogoutRedirectUri = GetPostLogoutRedirectUri();
                    
                    var logoutUrl = $"{authority}/protocol/openid-connect/logout" +
                                   $"?client_id={Uri.EscapeDataString(clientId)}" +
                                   $"&post_logout_redirect_uri={Uri.EscapeDataString(postLogoutRedirectUri)}";
                    
                    return logoutUrl;
                }
            }
            
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Error getting Keycloak logout URL");
            return null;
        }
    }

    /// <summary>
    /// Gets the post-logout redirect URI, handling both absolute and relative URLs
    /// </summary>
    private string GetPostLogoutRedirectUri()
    {
        var redirectUrl = _options.Logout.PostLogoutRedirectUrl;
        
        // If it's a relative URL, make it absolute
        if (!Uri.IsWellFormedUriString(redirectUrl, UriKind.Absolute))
        {
            var request = HttpContext.Request;
            var baseUrl = $"{request.Scheme}://{request.Host}";
            redirectUrl = new Uri(new Uri(baseUrl), redirectUrl).ToString();
        }
        
        return redirectUrl;
    }
}