using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

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
            Console.WriteLine("=== Starting Comprehensive Logout Process ===");
            
            // Clear all session data first
            try
            {
                if (HttpContext.Session != null)
                {
                    HttpContext.Session.Clear();
                    Console.WriteLine("Session data cleared");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Session clear error: {ex.Message}");
            }
            
            // Sign out from XAF Security System first
            // This properly clears the XAF security session that was established in the middleware
            try
            {
                if (HttpContext.User.Identity.IsAuthenticated)
                {
                    Console.WriteLine($"User is authenticated: {HttpContext.User.Identity.Name}");
                    Console.WriteLine($"Authentication type: {HttpContext.User.Identity.AuthenticationType}");
                    
                    // Get SignInManager service (using reflection to avoid compile-time type issues)
                    var serviceType = Type.GetType("DevExpress.ExpressApp.Security.Authentication.ClientServer.SignInManager, DevExpress.ExpressApp.Security.Blazor.v25.1");
                    if (serviceType != null)
                    {
                        Console.WriteLine("Found SignInManager type");
                        var signInManager = HttpContext.RequestServices.GetService(serviceType);
                        if (signInManager != null)
                        {
                            Console.WriteLine("Got SignInManager service instance");
                            
                            // Call SignOut method using reflection
                            var signOutMethod = serviceType.GetMethod("SignOut", Type.EmptyTypes);
                            if (signOutMethod != null)
                            {
                                Console.WriteLine("Found SignOut method, invoking...");
                                signOutMethod.Invoke(signInManager, null);
                                Console.WriteLine("Successfully signed out from XAF Security System");
                            }
                            else
                            {
                                Console.WriteLine("SignOut method not found on SignInManager");
                            }
                        }
                        else
                        {
                            Console.WriteLine("SignInManager service not found in DI container");
                        }
                    }
                    else
                    {
                        Console.WriteLine("SignInManager type not found");
                    }
                }
                else
                {
                    Console.WriteLine("User is not authenticated");
                }
            }
            catch (Exception ex)
            {
                // Log the error but continue with logout process
                // This ensures user can still log out even if XAF logout fails
                Console.WriteLine($"XAF logout error: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
            
            Console.WriteLine("Proceeding with comprehensive ASP.NET Core logout...");
            
            // Clear all authentication schemes
            try
            {
                // Sign out from all possible authentication schemes
                var authSchemes = new[]
                {
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    OpenIdConnectDefaults.AuthenticationScheme,
                    "Keycloak",
                    "Cookies",
                    "oidc"
                };

                foreach (var scheme in authSchemes)
                {
                    try
                    {
                        await HttpContext.SignOutAsync(scheme);
                        Console.WriteLine($"Signed out from scheme: {scheme}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to sign out from scheme {scheme}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Comprehensive sign out error: {ex.Message}");
            }
            
            // Clear any additional cookies manually
            try
            {
                var cookiesToClear = new[]
                {
                    ".AspNetCore.Identity.Application",
                    ".AspNetCore.Antiforgery",
                    ".AspNetCore.Session",
                    "XafSecurity",
                    "auth"
                };

                foreach (var cookieName in cookiesToClear)
                {
                    if (HttpContext.Request.Cookies.ContainsKey(cookieName))
                    {
                        HttpContext.Response.Cookies.Delete(cookieName);
                        Console.WriteLine($"Deleted cookie: {cookieName}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Cookie clearing error: {ex.Message}");
            }
            
            // Then, sign out from Keycloak (this will redirect to Keycloak logout page)
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("LogoutCallback", "Authentication")
            };
            
            Console.WriteLine("Redirecting to Keycloak for logout...");
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