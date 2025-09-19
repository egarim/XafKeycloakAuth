using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using System.Security.Claims;

namespace BlazorWebAssembly.Services;

public class AuthService : IAuthService
{
    private readonly IAccessTokenProvider _tokenProvider;
    private readonly AuthenticationStateProvider _authenticationStateProvider;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        IAccessTokenProvider tokenProvider,
        AuthenticationStateProvider authenticationStateProvider,
        ILogger<AuthService> logger)
    {
        _tokenProvider = tokenProvider;
        _authenticationStateProvider = authenticationStateProvider;
        _logger = logger;
    }

    public async Task<string?> GetAccessTokenAsync()
    {
        try
        {
            var tokenResult = await _tokenProvider.RequestAccessToken();
            
            if (tokenResult.TryGetToken(out var token))
            {
                _logger.LogInformation("Access token retrieved successfully");
                return token.Value;
            }
            else
            {
                _logger.LogWarning("Failed to retrieve access token");
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving access token");
            return null;
        }
    }

    public async Task<ClaimsPrincipal?> GetCurrentUserAsync()
    {
        try
        {
            var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();
            return authState.User;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving current user");
            return null;
        }
    }

    public async Task<bool> IsInRoleAsync(string role)
    {
        try
        {
            var user = await GetCurrentUserAsync();
            return user?.IsInRole(role) ?? false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking user role: {Role}", role);
            return false;
        }
    }
}
