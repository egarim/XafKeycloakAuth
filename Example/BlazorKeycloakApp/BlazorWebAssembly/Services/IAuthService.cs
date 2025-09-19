using System.Security.Claims;

namespace BlazorWebAssembly.Services;

public interface IAuthService
{
    Task<string?> GetAccessTokenAsync();
    Task<ClaimsPrincipal?> GetCurrentUserAsync();
    Task<bool> IsInRoleAsync(string role);
}
