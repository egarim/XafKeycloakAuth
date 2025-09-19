using BlazorWebAssembly;
using BlazorWebAssembly.Services;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Configure HttpClient with base address
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

// Add configuration for API base URL
var apiBaseUrl = builder.Configuration["ApiSettings:BaseUrl"] ?? "https://localhost:7002";

// Configure OIDC authentication for Keycloak
builder.Services.AddOidcAuthentication(options =>
{
    var keycloakConfig = builder.Configuration.GetSection("Keycloak");
    
    options.ProviderOptions.Authority = keycloakConfig["Authority"];
    options.ProviderOptions.ClientId = keycloakConfig["ClientId"];
    options.ProviderOptions.ResponseType = "code";
    
    // Configure redirect URIs
    var baseAddress = builder.HostEnvironment.BaseAddress;
    options.ProviderOptions.RedirectUri = $"{baseAddress}authentication/login-callback";
    options.ProviderOptions.PostLogoutRedirectUri = $"{baseAddress}authentication/logout-callback";
    
    // Configure scopes
    var scopes = keycloakConfig.GetSection("Scopes").Get<string[]>() ?? new[] { "openid", "profile", "email" };
    options.ProviderOptions.DefaultScopes.Clear();
    foreach (var scope in scopes)
    {
        options.ProviderOptions.DefaultScopes.Add(scope);
    }
    
    // Map claims for Keycloak compatibility
    options.UserOptions.NameClaim = "preferred_username";
    options.UserOptions.RoleClaim = "roles";
    
    // Configure additional parameters for Keycloak compatibility
    options.ProviderOptions.AdditionalProviderParameters.Add("response_mode", "query");
});

// Register custom services
builder.Services.AddScoped<IApiService, ApiService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IApiDiagnosticsService, ApiDiagnosticsService>();

// Configure HttpClient for API calls with authentication
builder.Services.AddHttpClient("API", client =>
{
    client.BaseAddress = new Uri(apiBaseUrl);
})
.AddHttpMessageHandler(sp =>
{
    var handler = sp.GetRequiredService<AuthorizationMessageHandler>()
        .ConfigureHandler(
            authorizedUrls: new[] { apiBaseUrl },
            scopes: new[] { "openid", "profile", "email" });
    return handler;
});

await builder.Build().RunAsync();
