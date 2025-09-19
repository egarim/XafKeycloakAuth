using BlazorServer.Services;
using System.Net.Http.Headers;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;

namespace BlazorServer.Services;

public interface IApiDiagnosticsService
{
    Task<ApiTestResult> TestEndpointAsync(string endpoint, bool requiresAuth = true);
    Task<string> AnalyzeTokenAsync();
    Task<string> CheckApiConfigurationAsync();
}

public class ApiTestResult
{
    public bool Success { get; set; }
    public int StatusCode { get; set; }
    public string? ReasonPhrase { get; set; }
    public string? Content { get; set; }
    public string? ErrorMessage { get; set; }
    public Dictionary<string, string> RequestHeaders { get; set; } = new();
    public Dictionary<string, string> ResponseHeaders { get; set; } = new();
    public TimeSpan Duration { get; set; }
}

public class ApiDiagnosticsService : IApiDiagnosticsService
{
    private readonly HttpClient _httpClient;
    private readonly IAuthService _authService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ApiDiagnosticsService> _logger;

    public ApiDiagnosticsService(
        HttpClient httpClient, 
        IAuthService authService, 
        IConfiguration configuration,
        ILogger<ApiDiagnosticsService> logger)
    {
        _httpClient = httpClient;
        _authService = authService;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<ApiTestResult> TestEndpointAsync(string endpoint, bool requiresAuth = true)
    {
        var result = new ApiTestResult();
        var startTime = DateTime.UtcNow;

        try
        {
            // Prepare request
            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);

            if (requiresAuth)
            {
                var accessToken = await _authService.GetAccessTokenAsync();
                if (!string.IsNullOrEmpty(accessToken))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    result.RequestHeaders["Authorization"] = $"Bearer {accessToken.Substring(0, Math.Min(20, accessToken.Length))}...";
                }
                else
                {
                    result.ErrorMessage = "No access token available";
                    return result;
                }
            }

            // Add request headers to result
            foreach (var header in request.Headers)
            {
                result.RequestHeaders[header.Key] = string.Join(", ", header.Value);
            }

            // Make request
            var response = await _httpClient.SendAsync(request);
            result.Duration = DateTime.UtcNow - startTime;

            // Capture response details
            result.StatusCode = (int)response.StatusCode;
            result.ReasonPhrase = response.ReasonPhrase;
            result.Content = await response.Content.ReadAsStringAsync();
            result.Success = response.IsSuccessStatusCode;

            // Add response headers to result
            foreach (var header in response.Headers)
            {
                result.ResponseHeaders[header.Key] = string.Join(", ", header.Value);
            }

            // Add content headers
            foreach (var header in response.Content.Headers)
            {
                result.ResponseHeaders[$"Content-{header.Key}"] = string.Join(", ", header.Value);
            }

            if (!result.Success)
            {
                result.ErrorMessage = $"HTTP {result.StatusCode}: {result.ReasonPhrase}";
            }
        }
        catch (Exception ex)
        {
            result.Duration = DateTime.UtcNow - startTime;
            result.ErrorMessage = ex.Message;
            result.Success = false;
        }

        return result;
    }

    public async Task<string> AnalyzeTokenAsync()
    {
        var analysis = new System.Text.StringBuilder();
        
        try
        {
            var accessToken = await _authService.GetAccessTokenAsync();
            
            if (string.IsNullOrEmpty(accessToken))
            {
                analysis.AppendLine("❌ No access token available");
                return analysis.ToString();
            }

            analysis.AppendLine("✅ Access token retrieved successfully");
            analysis.AppendLine($"Token length: {accessToken.Length} characters");
            analysis.AppendLine();

            // Parse JWT
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(accessToken))
            {
                analysis.AppendLine("❌ Token is not a valid JWT");
                return analysis.ToString();
            }

            var token = handler.ReadJwtToken(accessToken);
            
            analysis.AppendLine("📋 TOKEN DETAILS:");
            analysis.AppendLine($"  Algorithm: {token.Header.Alg}");
            analysis.AppendLine($"  Type: {token.Header.Typ}");
            analysis.AppendLine($"  Issuer: {token.Issuer}");
            analysis.AppendLine($"  Subject: {token.Subject}");
            analysis.AppendLine($"  Audience: {string.Join(", ", token.Audiences)}");
            analysis.AppendLine($"  Issued At: {token.IssuedAt:yyyy-MM-dd HH:mm:ss UTC}");
            analysis.AppendLine($"  Expires: {token.ValidTo:yyyy-MM-dd HH:mm:ss UTC}");
            analysis.AppendLine($"  Is Expired: {(DateTime.UtcNow > token.ValidTo ? "❌ YES" : "✅ NO")}");
            analysis.AppendLine();

            // Check audience match
            var expectedAudience = _configuration["Keycloak:Audience"] ?? "blazor-api";
            var audienceMatches = token.Audiences.Contains(expectedAudience);
            analysis.AppendLine($"🎯 AUDIENCE CHECK:");
            analysis.AppendLine($"  Expected: {expectedAudience}");
            analysis.AppendLine($"  Token Audiences: {string.Join(", ", token.Audiences)}");
            analysis.AppendLine($"  Match: {(audienceMatches ? "✅ YES" : "❌ NO")}");
            analysis.AppendLine();

            // Check issuer
            var expectedAuthority = _configuration["Keycloak:Authority"];
            var issuerMatches = token.Issuer == expectedAuthority;
            analysis.AppendLine($"🏛️ ISSUER CHECK:");
            analysis.AppendLine($"  Expected: {expectedAuthority}");
            analysis.AppendLine($"  Token Issuer: {token.Issuer}");
            analysis.AppendLine($"  Match: {(issuerMatches ? "✅ YES" : "❌ NO")}");
            analysis.AppendLine();

            // Analyze roles
            analysis.AppendLine($"👥 ROLES ANALYSIS:");
            var realmAccessClaim = token.Claims.FirstOrDefault(c => c.Type == "realm_access");
            if (realmAccessClaim != null)
            {
                try
                {
                    var realmAccess = JsonDocument.Parse(realmAccessClaim.Value);
                    if (realmAccess.RootElement.TryGetProperty("roles", out var roles))
                    {
                        analysis.AppendLine($"  Realm Roles: {string.Join(", ", roles.EnumerateArray().Select(r => r.GetString()))}");
                    }
                }
                catch (Exception ex)
                {
                    analysis.AppendLine($"  ❌ Error parsing realm_access: {ex.Message}");
                }
            }
            else
            {
                analysis.AppendLine($"  ❌ No realm_access claim found");
            }

            // Check for standard role claims
            var roleClaims = token.Claims.Where(c => c.Type == "role" || c.Type == "roles").ToList();
            if (roleClaims.Any())
            {
                analysis.AppendLine($"  Standard Role Claims: {string.Join(", ", roleClaims.Select(c => c.Value))}");
            }
            else
            {
                analysis.AppendLine($"  ❌ No standard role claims found");
            }
        }
        catch (Exception ex)
        {
            analysis.AppendLine($"❌ Error analyzing token: {ex.Message}");
            analysis.AppendLine($"Stack trace: {ex.StackTrace}");
        }

        return analysis.ToString();
    }

    public Task<string> CheckApiConfigurationAsync()
    {
        var config = new System.Text.StringBuilder();
        
        config.AppendLine("🔧 CONFIGURATION CHECK:");
        config.AppendLine();

        // Blazor Server config
        config.AppendLine("📱 BLAZOR SERVER CONFIG:");
        config.AppendLine($"  Authority: {_configuration["Keycloak:Authority"]}");
        config.AppendLine($"  ClientId: {_configuration["Keycloak:ClientId"]}");
        config.AppendLine($"  API Base URL: {_configuration["ApiSettings:BaseUrl"]}");
        config.AppendLine($"  Save Tokens: {_configuration["Keycloak:SaveTokens"]}");
        config.AppendLine();

        // Expected API config
        config.AppendLine("🔌 EXPECTED API CONFIG:");
        config.AppendLine($"  Authority: {_configuration["Keycloak:Authority"]}");
        config.AppendLine($"  Audience: blazor-api");
        config.AppendLine($"  CORS Origins: https://localhost:7001");
        config.AppendLine();

        // HTTP Client base address
        config.AppendLine("🌐 HTTP CLIENT CONFIG:");
        config.AppendLine($"  Base Address: {_httpClient.BaseAddress}");
        config.AppendLine($"  Default Headers: {_httpClient.DefaultRequestHeaders}");
        config.AppendLine();

        return Task.FromResult(config.ToString());
    }
}
