using System.Net.Http.Headers;
using System.Text.Json;

namespace BlazorWebAssembly.Services;

public class ApiService : IApiService
{
    private readonly HttpClient _httpClient;
    private readonly IAuthService _authService;
    private readonly ILogger<ApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public ApiService(IHttpClientFactory httpClientFactory, IAuthService authService, ILogger<ApiService> logger)
    {
        _httpClient = httpClientFactory.CreateClient("API");
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
                                  "- User lacks required role/permission\n" +
                                  "- Authorization policy not met\n" +
                                  "- Role claims missing from token";
                }
                
                return errorMessage;
            }
        }
        catch (HttpRequestException httpEx)
        {
            var errorMessage = $"Network error: {httpEx.Message}";
            _logger.LogError(httpEx, "Network error calling API endpoint: {Endpoint}", endpoint);
            
            // Add guidance for network issues
            errorMessage += "\n\nPossible causes:\n" +
                          "- API server is not running\n" +
                          "- Incorrect API base URL\n" +
                          "- CORS policy blocking request\n" +
                          "- Network connectivity issues";
            
            return errorMessage;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error calling API endpoint: {Endpoint}", endpoint);
            return $"Unexpected error: {ex.Message}";
        }
    }

    public async Task<bool> TestConnectionAsync()
    {
        try
        {
            using var client = new HttpClient();
            client.BaseAddress = _httpClient.BaseAddress;
            client.Timeout = TimeSpan.FromSeconds(10);
            
            var response = await client.GetAsync("/api/values");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Connection test failed");
            return false;
        }
    }

    private async Task SetAuthorizationHeaderAsync()
    {
        var accessToken = await _authService.GetAccessTokenAsync();
        
        if (!string.IsNullOrEmpty(accessToken))
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            _logger.LogDebug("Authorization header set with Bearer token");
        }
        else
        {
            _httpClient.DefaultRequestHeaders.Authorization = null;
            _logger.LogWarning("No access token available for API call");
        }
    }
}
