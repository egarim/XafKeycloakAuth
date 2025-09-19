using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using Xaf.Blazor.KeycloakAuth.Authentication;
using Xaf.Blazor.KeycloakAuth.Configuration;
using Xaf.Blazor.KeycloakAuth.Controllers;
using Xaf.Blazor.KeycloakAuth.Middleware;

namespace Xaf.Blazor.KeycloakAuth.Extensions;

/// <summary>
/// Extension methods for setting up Keycloak authentication in an application.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Keycloak authentication services to the service collection.
    /// This method configures OpenID Connect authentication, registers the Keycloak authentication provider,
    /// and sets up necessary services for proper integration with XAF Security System.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">The configuration</param>
    /// <param name="configureOptions">Optional configuration action for XafKeycloakOptions</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddXafKeycloakAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<XafKeycloakOptions>? configureOptions = null)
    {
        return services.AddXafKeycloakAuthentication(configuration, "Authentication:Keycloak", configureOptions);
    }

    /// <summary>
    /// Adds Keycloak authentication services to the service collection with custom configuration section.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">The configuration</param>
    /// <param name="configurationSectionKey">The configuration section key</param>
    /// <param name="configureOptions">Optional configuration action for XafKeycloakOptions</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddXafKeycloakAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        string configurationSectionKey,
        Action<XafKeycloakOptions>? configureOptions = null)
    {
        // Configure options
        var optionsBuilder = services.Configure<XafKeycloakOptions>(configuration.GetSection(configurationSectionKey));
        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }

        // Validate configuration
        services.AddSingleton<IValidateOptions<XafKeycloakOptions>, XafKeycloakOptionsValidator>();

        // Get the options for immediate use
        var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetRequiredService<IOptions<XafKeycloakOptions>>().Value;

        // Configure authentication
        var authBuilder = services.AddAuthentication(defaultScheme: CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, cookie =>
            {
                cookie.LoginPath = "/login";
                cookie.LogoutPath = "/logout";
                cookie.Cookie.Name = "XafKeycloakAuth";
                cookie.ExpireTimeSpan = options.Authentication.Cookie.ExpireTimeSpan;
                cookie.SlidingExpiration = true;
            });

        // Add OpenID Connect authentication
        authBuilder.AddOpenIdConnect(options.Authentication.SchemeName, oidc =>
        {
            oidc.Authority = options.Server.Authority;
            oidc.ClientId = options.Server.ClientId;
            oidc.ClientSecret = options.Server.ClientSecret;
            oidc.ResponseType = "code";
            oidc.RequireHttpsMetadata = options.Server.RequireHttpsMetadata;
            oidc.GetClaimsFromUserInfoEndpoint = true;
            oidc.SaveTokens = true;

            // Add scopes
            oidc.Scope.Clear();
            oidc.Scope.Add("openid");
            oidc.Scope.Add("profile");
            oidc.Scope.Add("email");
            foreach (var scope in options.Server.AdditionalScopes)
            {
                oidc.Scope.Add(scope);
            }

            // Configure callback paths
            oidc.CallbackPath = "/signin-oidc";
            oidc.SignedOutCallbackPath = "/signout-callback-oidc";
        });

        // If password authentication is enabled, add it as an additional scheme
        if (options.Authentication.EnablePasswordAuthentication)
        {
            // Register a simple authentication handler for password-based authentication
            // This is necessary to prevent XAF from automatically re-authenticating users after logout
            authBuilder.AddScheme<AuthenticationSchemeOptions, DummyPasswordAuthenticationHandler>(
                "Password", 
                "Password Authentication", 
                opts => { });
        }

        // Add controllers
        services.AddControllers()
            .AddApplicationPart(typeof(KeycloakAuthenticationController).Assembly);

        return services;
    }
}

/// <summary>
/// Dummy password authentication handler to enable multiple authentication methods.
/// This prevents XAF from automatically re-authenticating users after logout.
/// </summary>
public class DummyPasswordAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public DummyPasswordAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, 
        ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Always return no result - this handler is just for registration purposes
        return Task.FromResult(AuthenticateResult.NoResult());
    }
}

/// <summary>
/// Validates XafKeycloakOptions configuration.
/// </summary>
public class XafKeycloakOptionsValidator : IValidateOptions<XafKeycloakOptions>
{
    public ValidateOptionsResult Validate(string? name, XafKeycloakOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrEmpty(options.Server.Authority))
            failures.Add("Server.Authority is required");

        if (string.IsNullOrEmpty(options.Server.ClientId))
            failures.Add("Server.ClientId is required");

        if (string.IsNullOrEmpty(options.Server.ClientSecret))
            failures.Add("Server.ClientSecret is required");

        if (string.IsNullOrEmpty(options.Authentication.SchemeName))
            failures.Add("Authentication.SchemeName is required");

        return failures.Count > 0 
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}

/// <summary>
/// Extension methods for configuring the application pipeline.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the complete Keycloak authentication pipeline to the application.
    /// This method should be called after UseXaf() in the Configure method.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseXafKeycloakAuthentication(this IApplicationBuilder app)
    {
        // Add the Keycloak-XAF bridge middleware
        // This must be called AFTER UseXaf() but BEFORE any XAF-specific middleware
        app.UseKeycloakXafBridge();
        
        return app;
    }
}