namespace Xaf.Blazor.KeycloakAuth.Configuration;

/// <summary>
/// Configuration options for Keycloak authentication integration with XAF
/// </summary>
public class XafKeycloakOptions
{
    /// <summary>
    /// Keycloak server configuration
    /// </summary>
    public KeycloakServerOptions Server { get; set; } = new();
    
    /// <summary>
    /// User creation and mapping options
    /// </summary>
    public UserMappingOptions UserMapping { get; set; } = new();
    
    /// <summary>
    /// Authentication behavior options
    /// </summary>
    public AuthenticationOptions Authentication { get; set; } = new();
    
    /// <summary>
    /// Logout behavior options
    /// </summary>
    public LogoutOptions Logout { get; set; } = new();
}

/// <summary>
/// Keycloak server connection and client configuration
/// </summary>
public class KeycloakServerOptions
{
    /// <summary>
    /// Keycloak authority URL (e.g., "http://localhost:8080/realms/my-realm")
    /// </summary>
    public string Authority { get; set; } = string.Empty;
    
    /// <summary>
    /// OAuth2/OIDC Client ID
    /// </summary>
    public string ClientId { get; set; } = string.Empty;
    
    /// <summary>
    /// OAuth2/OIDC Client Secret
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;
    
    /// <summary>
    /// Whether to require HTTPS metadata (false for development)
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;
    
    /// <summary>
    /// OAuth2 response type (default: "code")
    /// </summary>
    public string ResponseType { get; set; } = "code";
    
    /// <summary>
    /// Callback path for authentication (default: "/signin-oidc")
    /// </summary>
    public string CallbackPath { get; set; } = "/signin-oidc";
    
    /// <summary>
    /// Signed out callback path (default: "/signout-callback-oidc")
    /// </summary>
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";
    
    /// <summary>
    /// Whether to get claims from user info endpoint (default: true)
    /// </summary>
    public bool GetClaimsFromUserInfoEndpoint { get; set; } = true;
    
    /// <summary>
    /// Whether to save tokens in cookie (default: true)
    /// </summary>
    public bool SaveTokens { get; set; } = true;
    
    /// <summary>
    /// Whether to use PKCE (default: false)
    /// </summary>
    public bool UsePkce { get; set; } = false;
    
    /// <summary>
    /// Additional OAuth2 scopes to request
    /// </summary>
    public List<string> AdditionalScopes { get; set; } = new();
}

/// <summary>
/// Options for mapping Keycloak user claims to XAF user properties
/// </summary>
public class UserMappingOptions
{
    /// <summary>
    /// Whether to automatically create users on first login (default: true)
    /// </summary>
    public bool AutoCreateUsers { get; set; } = true;
    
    /// <summary>
    /// Default role name to assign to new users (default: "Default")
    /// </summary>
    public string DefaultRoleName { get; set; } = "Default";
    
    /// <summary>
    /// Whether to create default role if it doesn't exist (default: true)
    /// </summary>
    public bool CreateDefaultRoleIfMissing { get; set; } = true;
    
    /// <summary>
    /// Claim mappings for user properties
    /// Key: User property name, Value: Keycloak claim name
    /// </summary>
    public Dictionary<string, string> PropertyMappings { get; set; } = new()
    {
        { "FirstName", "given_name" },
        { "LastName", "family_name" },
        { "DisplayName", "name" },
        { "Email", "email" }
    };
    
    /// <summary>
    /// Additional role mappings from Keycloak roles to XAF roles
    /// Key: Keycloak role name, Value: XAF role name
    /// </summary>
    public Dictionary<string, string> RoleMappings { get; set; } = new();
    
    /// <summary>
    /// Custom user creation action
    /// </summary>
    public Action<object, Dictionary<string, object>>? CustomUserCreation { get; set; }
}

/// <summary>
/// Authentication behavior configuration
/// </summary>
public class AuthenticationOptions
{
    /// <summary>
    /// Authentication scheme name (default: "Keycloak")
    /// </summary>
    public string SchemeName { get; set; } = "Keycloak";
    
    /// <summary>
    /// Display name for the authentication scheme (default: "Keycloak")
    /// </summary>
    public string DisplayName { get; set; } = "Keycloak";
    
    /// <summary>
    /// Whether to enable password authentication alongside Keycloak (default: true)
    /// This is required to prevent automatic re-authentication after logout
    /// </summary>
    public bool EnablePasswordAuthentication { get; set; } = true;
    
    /// <summary>
    /// Password authentication options
    /// </summary>
    public PasswordAuthenticationOptions PasswordOptions { get; set; } = new();
    
    /// <summary>
    /// Cookie authentication options
    /// </summary>
    public CookieOptions Cookie { get; set; } = new();
}

/// <summary>
/// Password authentication configuration
/// </summary>
public class PasswordAuthenticationOptions
{
    /// <summary>
    /// Whether to support password changes (default: true)
    /// </summary>
    public bool IsSupportChangePassword { get; set; } = true;
}

/// <summary>
/// Cookie authentication configuration
/// </summary>
public class CookieOptions
{
    /// <summary>
    /// Login path (default: "/LoginPage")
    /// </summary>
    public string LoginPath { get; set; } = "/LoginPage";
    
    /// <summary>
    /// Cookie expiration time (default: 60 minutes)
    /// </summary>
    public TimeSpan ExpireTimeSpan { get; set; } = TimeSpan.FromMinutes(60);
    
    /// <summary>
    /// Whether to use sliding expiration (default: true)
    /// </summary>
    public bool SlidingExpiration { get; set; } = true;
}

/// <summary>
/// Logout behavior configuration
/// </summary>
public class LogoutOptions
{
    /// <summary>
    /// Whether to enable comprehensive logout (XAF + ASP.NET Core + Keycloak) (default: true)
    /// </summary>
    public bool EnableComprehensiveLogout { get; set; } = true;
    
    /// <summary>
    /// URL to redirect to after logout (default: "/")
    /// </summary>
    public string PostLogoutRedirectUrl { get; set; } = "/";
    
    /// <summary>
    /// Whether to enable XAF SignInManager logout via reflection (default: true)
    /// </summary>
    public bool EnableXafSignInManagerLogout { get; set; } = true;
    
    /// <summary>
    /// Custom logout endpoint path (default: "/api/Authentication/Logout")
    /// </summary>
    public string LogoutEndpoint { get; set; } = "/api/Authentication/Logout";
    
    /// <summary>
    /// Whether to enable external authentication logout endpoint (default: true)
    /// </summary>
    public bool EnableExternalAuthLogout { get; set; } = true;
    
    /// <summary>
    /// External authentication logout endpoint (default: "/ExternalAuth/Logout")
    /// </summary>
    public string ExternalAuthLogoutEndpoint { get; set; } = "/ExternalAuth/Logout";
}