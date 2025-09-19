using BlazorServer.Services;
using System.Net.Http.Headers;
using System.Text.Json;

namespace BlazorServer.Services;

public interface IApiService
{
    Task<T?> GetAsync<T>(string endpoint);
    Task<string> GetRawAsync(string endpoint);
    Task<bool> TestConnectionAsync();
}

public class ApiService : IApiService
{
    private readonly HttpClient _httpClient;
    private readonly IAuthService _authService;
    private readonly ILogger<ApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public ApiService(HttpClient httpClient, IAuthService authService, ILogger<ApiService> logger)
    {
        _httpClient = httpClient;
        _authService = authService;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };
    }

    public async Task<T?> GetAsync<T>(string endpoint)
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            
            var response = await _httpClient.GetAsync(endpoint);
            
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<T>(content, _jsonOptions);
            }
            else
            {
                _logger.LogWarning("API call failed: {StatusCode} - {Reason}", response.StatusCode, response.ReasonPhrase);
                return default(T);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calling API endpoint: {Endpoint}", endpoint);
            return default(T);
        }
    }

    public async Task<string> GetRawAsync(string endpoint)
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            
            var response = await _httpClient.GetAsync(endpoint);
            var content = await response.Content.ReadAsStringAsync();
            
            // Log detailed information about the request
            _logger.LogInformation("API Request: {Method} {Endpoint}", "GET", endpoint);
            _logger.LogInformation("Response Status: {StatusCode} {ReasonPhrase}", response.StatusCode, response.ReasonPhrase);
            
            if (response.IsSuccessStatusCode)
            {
                return content;
            }
            else
            {
                // Enhanced error reporting
                var errorDetails = new
                {
                    StatusCode = (int)response.StatusCode,
                    ReasonPhrase = response.ReasonPhrase,
                    Content = content,
                    Headers = response.Headers.ToString(),
                    RequestHeaders = _httpClient.DefaultRequestHeaders.ToString()
                };
                
                var errorMessage = $"Error {response.StatusCode} ({response.ReasonPhrase}): {content}";
                
                // Add specific guidance for common authentication errors
                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    errorMessage += "\n\nPossible causes:\n" +
                                  "- Access token is missing or invalid\n" +
                                  "- Token has expired\n" +
                                  "- API audience mismatch\n" +
                                  "- JWT validation failed on API side";
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    errorMessage += "\n\nPossible causes:\n" +
                                  "- User doesn't have required role/permission\n" +
                                  "- Role claims not properly mapped\n" +
                                  "- Authorization policy mismatch";
                }
                
                _logger.LogWarning("API call failed with detailed info: {@ErrorDetails}", errorDetails);
                return errorMessage;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calling API endpoint: {Endpoint}", endpoint);
            return $"Exception: {ex.Message}\n\nStack Trace: {ex.StackTrace}";
        }
    }

    public async Task<bool> TestConnectionAsync()
    {
        try
        {
            // Test public endpoint first (no auth required)
            var response = await _httpClient.GetAsync("/api/values");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "API connection test failed");
            return false;
        }
    }

    private async Task SetAuthorizationHeaderAsync()
    {
        var accessToken = await _authService.GetAccessTokenAsync();
        
        if (!string.IsNullOrEmpty(accessToken))
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            _logger.LogInformation("Authorization header set with token: {TokenPrefix}... (length: {TokenLength})", 
                accessToken.Substring(0, Math.Min(20, accessToken.Length)), accessToken.Length);
                
            // Log token expiration for debugging
            try
            {
                var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                var jsonToken = handler.ReadJwtToken(accessToken);
                var isExpired = DateTime.UtcNow > jsonToken.ValidTo;
                _logger.LogInformation("Token expires at: {ExpiryTime} UTC, Is Expired: {IsExpired}", 
                    jsonToken.ValidTo, isExpired);
                    
                if (isExpired)
                {
                    _logger.LogWarning("Access token is EXPIRED!");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Could not parse JWT token: {Error}", ex.Message);
            }
        }
        else
        {
            _httpClient.DefaultRequestHeaders.Authorization = null;
            _logger.LogWarning("No access token available for API call");
        }
    }
}
