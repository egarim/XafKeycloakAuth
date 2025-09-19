using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace BlazorApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthTestController : ControllerBase
{
    /// <summary>
    /// Test endpoint to check if API is running - no authentication required
    /// </summary>
    [HttpGet("ping")]
    public IActionResult Ping()
    {
        return Ok(new
        {
            Message = "API is running",
            Timestamp = DateTime.UtcNow,
            Version = "1.0",
            Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Unknown"
        });
    }

    /// <summary>
    /// Analyze the provided JWT token and return detailed information
    /// </summary>
    [HttpGet("analyze-token")]
    [Authorize]
    public IActionResult AnalyzeToken()
    {
        try
        {
            var user = HttpContext.User;
            var authHeader = HttpContext.Request.Headers.Authorization.FirstOrDefault();
            
            // Extract token from Authorization header
            string? token = null;
            if (authHeader?.StartsWith("Bearer ") == true)
            {
                token = authHeader.Substring("Bearer ".Length);
            }

            var analysis = new
            {
                AuthenticationStatus = new
                {
                    IsAuthenticated = user.Identity?.IsAuthenticated ?? false,
                    AuthenticationType = user.Identity?.AuthenticationType,
                    Name = user.Identity?.Name
                },
                TokenInfo = GetTokenInfo(token),
                Claims = user.Claims.Select(c => new { c.Type, c.Value }).ToList(),
                Roles = new
                {
                    StandardRoles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList(),
                    RealmRoles = user.FindAll("role").Select(c => c.Value).ToList(),
                    HasAdminRole = user.IsInRole("admin"),
                    HasUserRole = user.IsInRole("user")
                },
                Policies = new
                {
                    RequireAdmin = user.IsInRole("admin"),
                    RequireUser = user.IsInRole("user") || user.IsInRole("admin")
                },
                Timestamp = DateTime.UtcNow
            };

            return Ok(analysis);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new
            {
                Error = "Failed to analyze token",
                Message = ex.Message,
                Timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Test authentication without any role requirements
    /// </summary>
    [HttpGet("auth-required")]
    [Authorize]
    public IActionResult AuthRequired()
    {
        return Ok(new
        {
            Message = "✅ Authentication successful! You have a valid token.",
            User = HttpContext.User.Identity?.Name,
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Test admin role requirement
    /// </summary>
    [HttpGet("admin-required")]
    [Authorize(Policy = "RequireAdmin")]
    public IActionResult AdminRequired()
    {
        return Ok(new
        {
            Message = "✅ Admin authentication successful! You have admin role.",
            User = HttpContext.User.Identity?.Name,
            AdminRoles = HttpContext.User.FindAll("role").Where(c => c.Value == "admin").Select(c => c.Value),
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Test user role requirement
    /// </summary>
    [HttpGet("user-required")]
    [Authorize(Policy = "RequireUser")]
    public IActionResult UserRequired()
    {
        return Ok(new
        {
            Message = "✅ User authentication successful! You have user or admin role.",
            User = HttpContext.User.Identity?.Name,
            UserRoles = HttpContext.User.FindAll("role").Where(c => c.Value == "user" || c.Value == "admin").Select(c => c.Value),
            Timestamp = DateTime.UtcNow
        });
    }

    private object? GetTokenInfo(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return new { Error = "No token provided" };
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
            {
                return new { Error = "Invalid JWT token format" };
            }

            var jwtToken = handler.ReadJwtToken(token);
            
            return new
            {
                Header = new
                {
                    jwtToken.Header.Alg,
                    jwtToken.Header.Typ,
                    jwtToken.Header.Kid
                },
                Payload = new
                {
                    Issuer = jwtToken.Issuer,
                    Audiences = jwtToken.Audiences.ToList(),
                    Subject = jwtToken.Subject,
                    IssuedAt = jwtToken.IssuedAt,
                    ValidFrom = jwtToken.ValidFrom,
                    ValidTo = jwtToken.ValidTo,
                    IsExpired = DateTime.UtcNow > jwtToken.ValidTo
                },
                Claims = jwtToken.Claims.Select(c => new { c.Type, c.Value }).ToList()
            };
        }
        catch (Exception ex)
        {
            return new { Error = $"Failed to parse token: {ex.Message}" };
        }
    }
}
