using System.Security.Claims;

namespace BlazorServer.Services;

public interface IAuthService
{
    Task<string?> GetAccessTokenAsync();
    Task<ClaimsPrincipal?> GetCurrentUserAsync();
    Task<bool> IsInRoleAsync(string role);
}
