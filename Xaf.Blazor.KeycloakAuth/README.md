# Xaf.Blazor.KeycloakAuth

A comprehensive NuGet package that provides seamless Keycloak OpenID Connect authentication integration for DevExpress XAF Blazor Server applications.

## ✨ Features

- 🚀 **Easy Setup**: Fluent configuration API with minimal boilerplate code
- 🔐 **Automatic User Creation**: Create XAF users automatically from Keycloak claims
- 🔄 **Proper Logout**: Solves the XAF automatic re-authentication issue
- 🌉 **Bridge Middleware**: Seamless integration between Keycloak and XAF Security System
- 📊 **Role Mapping**: Map Keycloak roles to XAF security roles
- 🛠️ **Configurable**: Extensive configuration options for different scenarios
- 📝 **Comprehensive Logging**: Full logging support for debugging and monitoring
- 🎯 **Generic Support**: Works with custom user types and XAF configurations

## 🎯 Problem Solved

This package specifically addresses the common XAF issue where **users are automatically re-authenticated after logout** when only OAuth authentication is configured. By providing multiple authentication methods (password + Keycloak), XAF disables its automatic re-authentication behavior.

## 🚀 Quick Start

### 1. Install the Package

```bash
dotnet add package Xaf.Blazor.KeycloakAuth
```

### 2. Configure Keycloak Settings

Add to your `appsettings.json`:

```json
{
  "Authentication": {
    "Keycloak": {
      "Authority": "http://localhost:8080/realms/your-realm",
      "ClientId": "your-client-id",
      "ClientSecret": "your-client-secret",
      "RequireHttpsMetadata": false
    }
  }
}
```

### 3. Configure Services in Startup.cs

```csharp
using Xaf.Blazor.KeycloakAuth.Extensions;

public void ConfigureServices(IServiceCollection services)
{
    // ... existing XAF configuration ...

    // Add Keycloak authentication
    services.AddXafKeycloakAuthentication(Configuration);

    services.AddXaf(Configuration, builder => {
        // ... existing XAF modules ...
        
        builder.Security
            .UseIntegratedMode(options => {
                // ... existing security options ...
            })
            // Add Keycloak authentication to XAF Security
            .AddKeycloakAuthentication();
    });
    
    // ... rest of configuration ...
}
```

### 4. Configure Pipeline in Startup.cs

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // ... existing middleware ...
    
    app.UseAuthentication();
    app.UseAuthorization();
    app.UseXaf();
    
    // Add Keycloak-XAF bridge middleware (AFTER UseXaf())
    app.UseXafKeycloakAuthentication();
    
    // ... rest of pipeline ...
}
```

### 5. Use Authentication

**Password Authentication**: Users can log in using standard XAF password authentication

**Keycloak Authentication**: Users can navigate to `/api/KeycloakAuthentication/Login/Keycloak` or create a button/link that points to this endpoint

**Logout**: Use the existing XAF logout functionality - it now works properly without automatic re-authentication!

## 🔧 Advanced Configuration

### Custom Configuration Options

```csharp
services.AddXafKeycloakAuthentication(Configuration, options =>
{
    // User creation and mapping
    options.UserMapping.AutoCreateUsers = true;
    options.UserMapping.DefaultRoleName = "User";
    options.UserMapping.PropertyMappings["Email"] = "email";
    options.UserMapping.PropertyMappings["FirstName"] = "given_name";
    options.UserMapping.PropertyMappings["LastName"] = "family_name";
    
    // Role mappings from Keycloak roles to XAF roles
    options.UserMapping.RoleMappings["admin"] = "Administrator";
    options.UserMapping.RoleMappings["user"] = "Default";
    
    // Authentication options
    options.Authentication.SchemeName = "Keycloak";
    options.Authentication.EnablePasswordAuthentication = true; // Required for proper logout
    
    // Logout options
    options.Logout.EnableComprehensiveLogout = true;
    options.Logout.PostLogoutRedirectUrl = "/";
    
    // Server options
    options.Server.AdditionalScopes.Add("roles");
});
```

### Custom User Types

For applications using custom user types:

```csharp
builder.Security
    .UseIntegratedMode(options => {
        options.UserType = typeof(MyCustomUser);
        options.UserLoginInfoType = typeof(MyCustomUserLoginInfo);
    })
    .AddKeycloakAuthentication<MyCustomUser, MyCustomUserLoginInfo, MyCustomRole>();
```

### Custom User Creation Logic

```csharp
services.AddXafKeycloakAuthentication(Configuration, options =>
{
    options.UserMapping.CustomUserCreation = (user, claims) =>
    {
        // Custom logic for setting additional user properties
        if (user is MyCustomUser customUser && claims.TryGetValue("department", out var dept))
        {
            customUser.Department = dept.ToString();
        }
    };
});
```

## 🔗 API Endpoints

The package provides several authentication endpoints:

- `POST /api/KeycloakAuthentication/Logout` - Comprehensive logout (XAF + Keycloak)
- `GET /api/KeycloakAuthentication/Login/Keycloak` - Initiate Keycloak authentication
- `POST /api/KeycloakAuthentication/Logout/External` - External authentication logout only

## 🛠️ Configuration Reference

### XafKeycloakOptions

| Property | Description | Default |
|----------|-------------|---------|
| `Server.Authority` | Keycloak realm URL | Required |
| `Server.ClientId` | OAuth2 client ID | Required |
| `Server.ClientSecret` | OAuth2 client secret | Required |
| `Server.RequireHttpsMetadata` | Require HTTPS for metadata | `true` |
| `UserMapping.AutoCreateUsers` | Auto-create users on first login | `true` |
| `UserMapping.DefaultRoleName` | Default role for new users | `"Default"` |
| `Authentication.EnablePasswordAuthentication` | Enable password auth (required for logout) | `true` |
| `Logout.EnableComprehensiveLogout` | Enable full logout functionality | `true` |

See the [XafKeycloakOptions.cs](Configuration/XafKeycloakOptions.cs) file for complete configuration options.

## 🧪 Testing

### Integration Test

After setup, test your authentication:

1. **Start your application**
2. **Test Password Authentication**: 
   - Navigate to your app URL
   - Should show XAF login page
   - Login with username/password
3. **Test Keycloak Authentication**:
   - Navigate to `/api/KeycloakAuthentication/Login/Keycloak`
   - Should redirect to Keycloak login
   - Login with Keycloak credentials
4. **Test Logout**:
   - Use XAF logout functionality
   - Verify user stays logged out (no automatic re-authentication)

## � Customization

The `KeycloakAuthenticationProvider` provides several virtual methods that can be overridden to customize behavior for different Keycloak configurations:

### Creating a Custom Authentication Provider

```csharp
public class CustomKeycloakAuthenticationProvider : KeycloakAuthenticationProvider<ApplicationUser, ApplicationUserLoginInfo, PermissionPolicyRole>
{
    public CustomKeycloakAuthenticationProvider(
        IPrincipalProvider principalProvider,
        ILogger<CustomKeycloakAuthenticationProvider> logger,
        IOptions<XafKeycloakOptions> options)
        : base(principalProvider, logger, options)
    {
    }

    /// <summary>
    /// Override to customize username extraction from claims
    /// </summary>
    protected override string? GetUserNameFromClaims(ClaimsPrincipal claimsPrincipal)
    {
        // Example: Use email as username instead of preferred_username
        return claimsPrincipal.FindFirst("email")?.Value ??
               claimsPrincipal.FindFirst("preferred_username")?.Value ??
               claimsPrincipal.FindFirst(ClaimTypes.Name)?.Value;
    }

    /// <summary>
    /// Override to customize user property mapping
    /// </summary>
    protected override void MapUserPropertiesFromClaims(ApplicationUser user, ClaimsPrincipal claimsPrincipal)
    {
        base.MapUserPropertiesFromClaims(user, claimsPrincipal);
        
        // Example: Map custom Keycloak attributes
        var department = claimsPrincipal.FindFirst("department")?.Value;
        if (!string.IsNullOrEmpty(department))
        {
            user.Department = department;
        }
        
        var employeeId = claimsPrincipal.FindFirst("employee_id")?.Value;
        if (!string.IsNullOrEmpty(employeeId))
        {
            user.EmployeeId = employeeId;
        }
    }

    /// <summary>
    /// Override to customize role assignment logic
    /// </summary>
    protected override void AssignUserRoles(IObjectSpace objectSpace, ApplicationUser user, ClaimsPrincipal claimsPrincipal)
    {
        // Example: Custom role mapping from realm_access roles
        var realmAccessClaim = claimsPrincipal.FindFirst("realm_access");
        if (realmAccessClaim != null)
        {
            try
            {
                var realmAccess = JsonSerializer.Deserialize<JsonElement>(realmAccessClaim.Value);
                if (realmAccess.TryGetProperty("roles", out var rolesElement))
                {
                    foreach (var roleElement in rolesElement.EnumerateArray())
                    {
                        var roleName = roleElement.GetString();
                        if (!string.IsNullOrEmpty(roleName))
                        {
                            // Map Keycloak roles to XAF roles
                            var xafRoleName = MapKeycloakRoleToXafRole(roleName);
                            if (!string.IsNullOrEmpty(xafRoleName))
                            {
                                var role = GetOrCreateRole(objectSpace, xafRoleName);
                                if (role != null)
                                {
                                    AssignRoleToUser(user, role);
                                }
                            }
                        }
                    }
                }
            }
            catch (JsonException ex)
            {
                Logger.LogWarning("Failed to parse realm_access claim: {Error}", ex.Message);
            }
        }
        
        // Always call base for default role assignment
        base.AssignUserRoles(objectSpace, user, claimsPrincipal);
    }

    private string? MapKeycloakRoleToXafRole(string keycloakRole)
    {
        return keycloakRole switch
        {
            "admin" => "Administrators",
            "manager" => "Managers", 
            "user" => "Users",
            _ => null // Ignore unmapped roles
        };
    }

    /// <summary>
    /// Override to customize Keycloak claim detection
    /// </summary>
    protected override bool HasKeycloakClaims(ClaimsPrincipal principal)
    {
        // Example: Look for custom issuer or additional claims
        var issuer = principal.FindFirst("iss")?.Value;
        return !string.IsNullOrEmpty(issuer) && issuer.Contains("keycloak");
    }
}
```

### Registering the Custom Provider

```csharp
// In Startup.cs or Program.cs
services.AddXafKeycloakAuthentication<ApplicationUser, ApplicationUserLoginInfo, PermissionPolicyRole>(options =>
{
    // Configure options...
})
.Services.AddScoped<IAuthenticationProvider, CustomKeycloakAuthenticationProvider>();
```

### Available Virtual Methods

- **`CanHandlePrincipal`**: Determine if the provider can handle the current principal
- **`HasKeycloakClaims`**: Check if claims indicate Keycloak authentication
- **`GetUserNameFromClaims`**: Extract username from claims
- **`CreateApplicationUser`**: Create new user objects from claims
- **`MapUserPropertiesFromClaims`**: Map claims to user properties
- **`AssignUserRoles`**: Assign roles based on claims
- **`AssignRoleToUser`**: Assign individual roles to users
- **`HasClaimValue`**: Check for specific claim values
- **`GetOrCreateRole`**: Get or create roles by name
- **`FindUserLoginInfo`**: Find existing login info records
- **`SetPropertyIfExists`**: Set object properties using reflection

## �🐛 Troubleshooting

### Common Issues

**Issue**: Users are automatically re-authenticated after logout
- **Solution**: Ensure `EnablePasswordAuthentication = true` in options
- **Cause**: XAF automatically re-authenticates when only one auth method is configured

**Issue**: Keycloak authentication fails
- **Solution**: Check Keycloak client configuration and redirect URIs
- **Debug**: Enable debug logging to see detailed authentication flow

**Issue**: User creation fails
- **Solution**: Check user property mappings and ensure required properties are set
- **Debug**: Review logs for specific property mapping errors

### Logging

Enable detailed logging in `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Xaf.Blazor.KeycloakAuth": "Debug",
      "Microsoft.AspNetCore.Authentication": "Debug"
    }
  }
}
```

## 📋 Requirements

- .NET 9.0 or later
- DevExpress XAF 25.1 or later
- ASP.NET Core Blazor Server application
- Keycloak server (any supported version)

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 🔗 Related Links

- [DevExpress XAF Documentation](https://docs.devexpress.com/eXpressAppFramework/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [ASP.NET Core Authentication](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/)

## 📊 Changelog

### v1.0.0
- Initial release
- Keycloak OpenID Connect authentication provider for XAF
- Bridge middleware for seamless XAF Security integration
- Configurable user creation and property mapping
- Enhanced logout functionality preventing automatic re-authentication
- Fluent configuration API for easy setup
- Support for multiple authentication methods
- Comprehensive logging and error handling