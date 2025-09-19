using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BlazorApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ValuesController : ControllerBase
{
    /// <summary>
    /// Public endpoint - no authentication required
    /// </summary>
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new { 
            Message = "Public endpoint working", 
            Values = new[] { "value1", "value2", "value3" },
            Timestamp = DateTime.UtcNow
        });
    }
    
    /// <summary>
    /// Protected endpoint - requires valid JWT token
    /// </summary>
    [HttpGet("protected")]
    [Authorize]
    public IActionResult GetProtected()
    {
        return Ok(new { 
            Message = "This is protected data - authentication successful!", 
            User = HttpContext.User.Identity?.Name,
            IsAuthenticated = HttpContext.User.Identity?.IsAuthenticated,
            AuthenticationType = HttpContext.User.Identity?.AuthenticationType,
            ClaimsCount = HttpContext.User.Claims.Count(),
            Timestamp = DateTime.UtcNow
        });
    }
    
    /// <summary>
    /// Admin-only endpoint - requires admin role
    /// </summary>
    [HttpGet("admin-only")]
    [Authorize(Policy = "RequireAdmin")]
    public IActionResult GetAdminOnly()
    {
        return Ok(new { 
            Message = "Admin only data - you have admin access!", 
            User = HttpContext.User.Identity?.Name,
            Roles = HttpContext.User.FindAll("role").Select(c => c.Value),
            Timestamp = DateTime.UtcNow
        });
    }
}
