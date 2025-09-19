namespace BlazorWebAssembly.Services;

public interface IApiService
{
    Task<T?> GetAsync<T>(string endpoint);
    Task<string> GetRawAsync(string endpoint);
    Task<bool> TestConnectionAsync();
}
