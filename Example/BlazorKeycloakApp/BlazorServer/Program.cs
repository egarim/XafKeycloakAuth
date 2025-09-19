using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using BlazorServer.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

// Configure authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    var keycloakConfig = builder.Configuration.GetSection("Keycloak");
    
    options.Authority = keycloakConfig["Authority"];
    options.ClientId = keycloakConfig["ClientId"];
    options.ClientSecret = keycloakConfig["ClientSecret"];
    options.RequireHttpsMetadata = false;
    options.ResponseType = "code";
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    
    // Set explicit callback paths
    options.CallbackPath = "/signin-oidc";
    options.SignedOutCallbackPath = "/signout-callback-oidc";
    options.RemoteSignOutPath = "/signout-oidc";
    
    // Configure logout redirect
    options.SignedOutRedirectUri = "https://localhost:7001/";
    
    // Enable PKCE (required by Keycloak setup)
    options.UsePkce = true;
    
    // Clear and add scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("roles");
    
    // Map claims
    options.TokenValidationParameters.NameClaimType = "preferred_username";
    options.TokenValidationParameters.RoleClaimType = "roles";
    
    // Configure for better stability
    options.MaxAge = TimeSpan.FromMinutes(30);
    options.UseTokenLifetime = true;
    
    options.Events = new OpenIdConnectEvents
    {
        OnTokenResponseReceived = context =>
        {
            if (context.Properties != null)
            {
                var tokens = new List<AuthenticationToken>();
                if (context.TokenEndpointResponse.AccessToken != null)
                {
                    tokens.Add(new AuthenticationToken { Name = "access_token", Value = context.TokenEndpointResponse.AccessToken });
                }
                if (context.TokenEndpointResponse.RefreshToken != null)
                {
                    tokens.Add(new AuthenticationToken { Name = "refresh_token", Value = context.TokenEndpointResponse.RefreshToken });
                }
                if (context.TokenEndpointResponse.IdToken != null)
                {
                    tokens.Add(new AuthenticationToken { Name = "id_token", Value = context.TokenEndpointResponse.IdToken });
                }
                context.Properties.StoreTokens(tokens);
            }
            return Task.CompletedTask;
        },
        OnUserInformationReceived = context =>
        {
            // Transform Keycloak roles
            if (context.User.RootElement.TryGetProperty("realm_access", out var realmAccess) &&
                realmAccess.TryGetProperty("roles", out var roles))
            {
                var identity = context.Principal?.Identity as ClaimsIdentity;
                if (identity != null)
                {
                    foreach (var role in roles.EnumerateArray())
                    {
                        identity.AddClaim(new Claim(ClaimTypes.Role, role.GetString() ?? ""));
                    }
                }
            }
            return Task.CompletedTask;
        },
        OnRedirectToIdentityProvider = context =>
        {
            // Ensure we're using the correct redirect URI
            if (string.IsNullOrEmpty(context.ProtocolMessage.RedirectUri))
            {
                context.ProtocolMessage.RedirectUri = "https://localhost:7001/signin-oidc";
            }
            return Task.CompletedTask;
        },
        OnRemoteFailure = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError("Authentication failed: {Error}", context.Failure?.Message);
            
            context.Response.Redirect("/welcome?error=auth_failed");
            context.HandleResponse();
            return Task.CompletedTask;
        },
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError("Authentication failed: {Error}", context.Exception?.Message);
            return Task.CompletedTask;
        }
    };
});

// Add HttpClient for API calls
builder.Services.AddHttpClient("ApiClient", client =>
{
    var apiSettings = builder.Configuration.GetSection("ApiSettings");
    client.BaseAddress = new Uri(apiSettings["BaseUrl"] ?? "https://localhost:7002");
});

// Register API service
builder.Services.AddScoped<BlazorServer.Services.IApiService>(provider =>
{
    var httpClientFactory = provider.GetRequiredService<IHttpClientFactory>();
    var httpClient = httpClientFactory.CreateClient("ApiClient");
    var authService = provider.GetRequiredService<BlazorServer.Services.IAuthService>();
    var logger = provider.GetRequiredService<ILogger<BlazorServer.Services.ApiService>>();
    return new BlazorServer.Services.ApiService(httpClient, authService, logger);
});

// Add authorization
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAuthentication", policy =>
        policy.RequireAuthenticatedUser());
    options.AddPolicy("RequireAdmin", policy =>
        policy.RequireRole("admin"));
    options.AddPolicy("RequireUser", policy =>
        policy.RequireRole("user", "admin"));
});

builder.Services.AddScoped<WeatherForecastService>();

// Register services
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<BlazorServer.Services.IAuthService, BlazorServer.Services.AuthService>();
builder.Services.AddScoped<BlazorServer.Services.IApiDiagnosticsService>(provider =>
{
    var httpClientFactory = provider.GetRequiredService<IHttpClientFactory>();
    var httpClient = httpClientFactory.CreateClient("ApiClient");
    var authService = provider.GetRequiredService<BlazorServer.Services.IAuthService>();
    var configuration = provider.GetRequiredService<IConfiguration>();
    var logger = provider.GetRequiredService<ILogger<BlazorServer.Services.ApiDiagnosticsService>>();
    return new BlazorServer.Services.ApiDiagnosticsService(httpClient, authService, configuration, logger);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

// Add auth endpoints
app.MapGet("/Account/Login", async (HttpContext context, string? returnUrl = null) =>
{
    var properties = new AuthenticationProperties
    {
        RedirectUri = returnUrl ?? "/"
    };
    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
});

app.MapPost("/Account/Logout", async (HttpContext context) =>
{
    var properties = new AuthenticationProperties
    {
        RedirectUri = "/welcome"
    };
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
});

app.Run();
