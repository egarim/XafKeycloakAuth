using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace BlazorServer.Services;

public class AuthService : IAuthService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<string?> GetAccessTokenAsync()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context?.User?.Identity?.IsAuthenticated == true)
        {
            return await context.GetTokenAsync("access_token");
        }
        return null;
    }

    public Task<ClaimsPrincipal?> GetCurrentUserAsync()
    {
        return Task.FromResult(_httpContextAccessor.HttpContext?.User);
    }

    public async Task<bool> IsInRoleAsync(string role)
    {
        var user = await GetCurrentUserAsync();
        return user?.IsInRole(role) ?? false;
    }
}
