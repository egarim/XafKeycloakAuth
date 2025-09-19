using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using DevExpress.ExpressApp.Security.Authentication.ClientServer;

namespace XafKeycloakAuth.Blazor.Server.Controllers
{
    [Route("api/[controller]")]
    public class AuthenticationController : Controller
    {
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = returnUrl ?? "/"
            };
            
            return Challenge(properties, "Keycloak");
        }

        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            // Sign out from XAF Security System first
            // This properly clears the XAF security session that was established in the middleware
            try
            {
                if (HttpContext.User.Identity.IsAuthenticated)
                {
                    // Get SignInManager service (using dynamic to avoid compile-time type issues)
                    var serviceType = Type.GetType("DevExpress.ExpressApp.Security.Authentication.ClientServer.SignInManager, DevExpress.ExpressApp.Security.Blazor.v25.1");
                    if (serviceType != null)
                    {
                        var signInManager = HttpContext.RequestServices.GetService(serviceType);
                        if (signInManager != null)
                        {
                            // Call SignOut method using reflection
                            var signOutMethod = serviceType.GetMethod("SignOut", Type.EmptyTypes);
                            signOutMethod?.Invoke(signInManager, null);
                            
                            Console.WriteLine("Successfully signed out from XAF Security System");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Log the error but continue with logout process
                // This ensures user can still log out even if XAF logout fails
                Console.WriteLine($"XAF logout error: {ex.Message}");
            }
            
            // Sign out from both local application and Keycloak
            // This prevents automatic re-login by clearing the Keycloak session
            
            // Sign out from local application (clears cookies)
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            
            // Then, sign out from Keycloak (this will redirect to Keycloak logout page)
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("LogoutCallback", "Authentication")
            };
            
            return SignOut(properties, OpenIdConnectDefaults.AuthenticationScheme);
        }
        
        [HttpGet]
        public IActionResult LogoutCallback()
        {
            // This is called after Keycloak logout completes
            // User is now fully signed out from XAF, local application, and Keycloak
            Console.WriteLine("Logout callback completed - user fully signed out");
            return Redirect("/");
        }
    }
}