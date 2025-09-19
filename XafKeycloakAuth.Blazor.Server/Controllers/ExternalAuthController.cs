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