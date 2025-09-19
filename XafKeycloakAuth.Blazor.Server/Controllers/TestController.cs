using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace XafKeycloakAuth.Blazor.Server.Controllers
{
    public class TestController : Controller
    {
        [HttpGet]
        public async Task<IActionResult> SimulateKeycloakAuth()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, "test-user-id"),
                new Claim(ClaimTypes.Name, "Test User"),
                new Claim(ClaimTypes.Email, "test@example.com"),
                new Claim("preferred_username", "testuser"),
                new Claim("iss", "http://localhost:8080/realms/XafKeycloakAuth"),
                new Claim("sub", "test-user-id")
            };

            var claimsIdentity = new ClaimsIdentity(claims, "Keycloak");
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);

            return Redirect("/");
        }

        [HttpGet]
        public async Task<IActionResult> ClearAuth()
        {
            await HttpContext.SignOutAsync();
            return Ok("Authentication cleared");
        }
    }
}