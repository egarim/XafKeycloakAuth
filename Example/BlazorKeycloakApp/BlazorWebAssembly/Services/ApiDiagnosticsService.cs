using System.Net.Http.Headers;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;

namespace BlazorWebAssembly.Services;

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
        IHttpClientFactory httpClientFactory, 
        IAuthService authService, 
        IConfiguration configuration,
        ILogger<ApiDiagnosticsService> logger)
    {
        _httpClient = httpClientFactory.CreateClient("API");
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

            // Process response
            result.StatusCode = (int)response.StatusCode;
            result.ReasonPhrase = response.ReasonPhrase;
            result.Success = response.IsSuccessStatusCode;

            // Add response headers to result
            foreach (var header in response.Headers)
            {
                result.ResponseHeaders[header.Key] = string.Join(", ", header.Value);
            }

            // Get response content
            result.Content = await response.Content.ReadAsStringAsync();

            if (!result.Success)
            {
                result.ErrorMessage = $"HTTP {result.StatusCode}: {result.ReasonPhrase}";
            }
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            result.Duration = DateTime.UtcNow - startTime;
            _logger.LogError(ex, "Error testing endpoint: {Endpoint}", endpoint);
        }

        return result;
    }

    public async Task<string> AnalyzeTokenAsync()
    {
        var analysis = new System.Text.StringBuilder();
        
        try
        {
            analysis.AppendLine("=== JWT TOKEN ANALYSIS ===");
            analysis.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            analysis.AppendLine();

            var accessToken = await _authService.GetAccessTokenAsync();
            
            if (string.IsNullOrEmpty(accessToken))
            {
                analysis.AppendLine("❌ NO ACCESS TOKEN AVAILABLE");
                analysis.AppendLine("- User might not be authenticated");
                analysis.AppendLine("- Token might have expired");
                analysis.AppendLine("- Authentication flow might have failed");
                return analysis.ToString();
            }

            analysis.AppendLine($"✅ Access Token Available ({accessToken.Length} characters)");
            analysis.AppendLine();

            // Decode JWT token
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadJwtToken(accessToken);

                analysis.AppendLine("📋 TOKEN HEADER:");
                analysis.AppendLine($"   - Algorithm: {token.Header.Alg}");
                analysis.AppendLine($"   - Type: {token.Header.Typ}");
                analysis.AppendLine($"   - Key ID: {token.Header.Kid ?? "Not specified"}");
                analysis.AppendLine();

                analysis.AppendLine("📋 TOKEN CLAIMS:");
                foreach (var claim in token.Claims.OrderBy(c => c.Type))
                {
                    var value = claim.Value;
                    if (value.Length > 100)
                    {
                        value = value.Substring(0, 100) + "...";
                    }
                    analysis.AppendLine($"   - {claim.Type}: {value}");
                }
                analysis.AppendLine();

                analysis.AppendLine("⏰ TOKEN TIMING:");
                analysis.AppendLine($"   - Issued At: {token.IssuedAt:yyyy-MM-dd HH:mm:ss UTC}");
                analysis.AppendLine($"   - Expires: {token.ValidTo:yyyy-MM-dd HH:mm:ss UTC}");
                analysis.AppendLine($"   - Valid For: {(token.ValidTo - DateTime.UtcNow).TotalMinutes:F1} minutes");
                
                if (token.ValidTo < DateTime.UtcNow)
                {
                    analysis.AppendLine("   ❌ TOKEN IS EXPIRED!");
                }
                else
                {
                    analysis.AppendLine("   ✅ Token is still valid");
                }
                analysis.AppendLine();

                // Check important claims
                analysis.AppendLine("🔍 CLAIM VALIDATION:");
                
                var audience = token.Claims.FirstOrDefault(c => c.Type == "aud")?.Value;
                analysis.AppendLine($"   - Audience (aud): {audience ?? "MISSING"}");
                
                var issuer = token.Claims.FirstOrDefault(c => c.Type == "iss")?.Value;
                analysis.AppendLine($"   - Issuer (iss): {issuer ?? "MISSING"}");
                
                var preferredUsername = token.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
                analysis.AppendLine($"   - Username: {preferredUsername ?? "MISSING"}");
                
                var realmAccess = token.Claims.FirstOrDefault(c => c.Type == "realm_access")?.Value;
                if (!string.IsNullOrEmpty(realmAccess))
                {
                    try
                    {
                        var realmAccessJson = JsonDocument.Parse(realmAccess);
                        if (realmAccessJson.RootElement.TryGetProperty("roles", out var roles))
                        {
                            var roleList = string.Join(", ", roles.EnumerateArray().Select(r => r.GetString()));
                            analysis.AppendLine($"   - Roles: {roleList}");
                        }
                    }
                    catch
                    {
                        analysis.AppendLine("   - Roles: Error parsing realm_access");
                    }
                }
                else
                {
                    analysis.AppendLine("   - Roles: MISSING realm_access claim");
                }
            }
            catch (Exception tokenEx)
            {
                analysis.AppendLine($"❌ TOKEN PARSING ERROR: {tokenEx.Message}");
            }
        }
        catch (Exception ex)
        {
            analysis.AppendLine($"❌ ANALYSIS ERROR: {ex.Message}");
            _logger.LogError(ex, "Error analyzing token");
        }

        return analysis.ToString();
    }

    public async Task<string> CheckApiConfigurationAsync()
    {
        var config = new System.Text.StringBuilder();
        
        try
        {
            config.AppendLine("=== API CONFIGURATION CHECK ===");
            config.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            config.AppendLine();

            // Check API base URL
            var apiBaseUrl = _configuration["ApiSettings:BaseUrl"];
            config.AppendLine($"🌐 API Base URL: {apiBaseUrl ?? "NOT CONFIGURED"}");
            
            if (string.IsNullOrEmpty(apiBaseUrl))
            {
                config.AppendLine("   ❌ API Base URL is not configured!");
            }
            else
            {
                config.AppendLine("   ✅ API Base URL is configured");
            }
            config.AppendLine();

            // Check Keycloak configuration
            config.AppendLine("🔐 KEYCLOAK CONFIGURATION:");
            var authority = _configuration["Keycloak:Authority"];
            var clientId = _configuration["Keycloak:ClientId"];
            
            config.AppendLine($"   - Authority: {authority ?? "NOT CONFIGURED"}");
            config.AppendLine($"   - Client ID: {clientId ?? "NOT CONFIGURED"}");
            config.AppendLine($"   - RequireHttpsMetadata: {_configuration["Keycloak:RequireHttpsMetadata"]}");
            
            var scopes = _configuration.GetSection("Keycloak:Scopes").Get<string[]>();
            if (scopes?.Length > 0)
            {
                config.AppendLine($"   - Scopes: {string.Join(", ", scopes)}");
            }
            else
            {
                config.AppendLine("   - Scopes: NOT CONFIGURED");
            }
            config.AppendLine();

            // Test API connectivity
            config.AppendLine("🔗 API CONNECTIVITY TEST:");
            try
            {
                var connectionResult = await TestConnectionAsync();
                if (connectionResult)
                {
                    config.AppendLine("   ✅ API is reachable");
                }
                else
                {
                    config.AppendLine("   ❌ API is not reachable");
                    config.AppendLine("   Check if the API server is running");
                }
            }
            catch (Exception connectEx)
            {
                config.AppendLine($"   ❌ Connection test failed: {connectEx.Message}");
            }
            config.AppendLine();

            // Configuration recommendations
            config.AppendLine("💡 CONFIGURATION RECOMMENDATIONS:");
            config.AppendLine("   1. Ensure API is running on the configured URL");
            config.AppendLine("   2. Verify Keycloak realm and client configuration");
            config.AppendLine("   3. Check CORS settings in the API");
            config.AppendLine("   4. Validate JWT audience claim matches API configuration");
        }
        catch (Exception ex)
        {
            config.AppendLine($"❌ CONFIGURATION CHECK ERROR: {ex.Message}");
            _logger.LogError(ex, "Error checking API configuration");
        }

        return config.ToString();
    }

    private async Task<bool> TestConnectionAsync()
    {
        try
        {
            using var client = new HttpClient();
            client.BaseAddress = _httpClient.BaseAddress;
            client.Timeout = TimeSpan.FromSeconds(10);
            
            var response = await client.GetAsync("/api/values");
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }
}
