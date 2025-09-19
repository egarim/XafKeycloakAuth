using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace BlazorApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UserController : ControllerBase
{
    /// <summary>
    /// Get current user profile with all claims and roles
    /// </summary>
    [HttpGet("profile")]
    public IActionResult GetProfile()
    {
        var user = HttpContext.User;
        
        return Ok(new
        {
            Username = user.Identity?.Name,
            IsAuthenticated = user.Identity?.IsAuthenticated ?? false,
            AuthenticationType = user.Identity?.AuthenticationType,
            Claims = user.Claims.Select(c => new { c.Type, c.Value }).ToList(),
            Roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList(),
            RealmRoles = user.FindAll("role").Select(c => c.Value).ToList(),
            Timestamp = DateTime.UtcNow
        });
    }
    
    /// <summary>
    /// Admin-only endpoint - requires admin role
    /// </summary>
    [HttpGet("admin-only")]
    [Authorize(Policy = "RequireAdmin")]
    public IActionResult AdminOnly()
    {
        return Ok(new { 
            Message = "This endpoint requires admin role - access granted!", 
            User = HttpContext.User.Identity?.Name,
            AdminRoles = HttpContext.User.FindAll("role").Where(c => c.Value == "admin").Select(c => c.Value),
            Timestamp = DateTime.UtcNow
        });
    }
    
    /// <summary>
    /// User data endpoint - requires user or admin role
    /// </summary>
    [HttpGet("user-data")]
    [Authorize(Policy = "RequireUser")]
    public IActionResult UserData()
    {
        return Ok(new { 
            Message = "This endpoint requires user or admin role - access granted!", 
            User = HttpContext.User.Identity?.Name,
            UserRoles = HttpContext.User.FindAll("role").Where(c => c.Value == "user" || c.Value == "admin").Select(c => c.Value),
            Timestamp = DateTime.UtcNow
        });
    }
}
