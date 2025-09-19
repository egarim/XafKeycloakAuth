using DevExpress.ExpressApp.Security;
using DevExpress.ExpressApp.ApplicationBuilder;
using DevExpress.ExpressApp.Blazor.ApplicationBuilder;
using DevExpress.ExpressApp.Blazor.Services;
using DevExpress.Persistent.Base;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.EntityFrameworkCore;
using XafKeycloakAuth.Blazor.Server.Services;
using DevExpress.Persistent.BaseImpl.EF.PermissionPolicy;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.OData;
using DevExpress.ExpressApp.WebApi.Services;
using XafKeycloakAuth.WebApi.JWT;
using DevExpress.ExpressApp.Security.Authentication;
using DevExpress.ExpressApp.Security.Authentication.ClientServer;
using Microsoft.AspNetCore.DataProtection;

namespace XafKeycloakAuth.Blazor.Server;

public class Startup {
    public Startup(IConfiguration configuration) {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
    public void ConfigureServices(IServiceCollection services) {
        services.AddSingleton(typeof(Microsoft.AspNetCore.SignalR.HubConnectionHandler<>), typeof(ProxyHubConnectionHandler<>));

        // Add data protection and session support to fix state parameter issues
        services.AddDataProtection()
            .SetApplicationName("XafKeycloakAuth");
        
        services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromMinutes(20);
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        });

        services.AddRazorPages();
        services.AddServerSideBlazor();
        services.AddHttpContextAccessor();
        services.AddScoped<IAuthenticationTokenProvider, JwtTokenProviderService>();
        services.AddScoped<CircuitHandler, CircuitHandlerProxy>();
        services.AddXaf(Configuration, builder => {
            builder.UseApplication<XafKeycloakAuthBlazorApplication>();

            builder.AddXafWebApi(webApiBuilder => {
                webApiBuilder.ConfigureOptions(options => {
                    // Make your business objects available in the Web API and generate the GET, POST, PUT, and DELETE HTTP methods for it.
                    // options.BusinessObject<YourBusinessObject>();
                });
            });

            builder.Modules
                .AddConditionalAppearance()
                .AddValidation(options => {
                    options.AllowValidationDetailsAccess = false;
                })
                .Add<XafKeycloakAuth.Module.XafKeycloakAuthModule>()
                .Add<XafKeycloakAuthBlazorModule>();
            builder.ObjectSpaceProviders
                .AddSecuredEFCore(options => {
                    options.PreFetchReferenceProperties();
                })
                .WithDbContext<XafKeycloakAuth.Module.BusinessObjects.XafKeycloakAuthEFCoreDbContext>((serviceProvider, options) => {
                    // Uncomment this code to use an in-memory database. This database is recreated each time the server starts. With the in-memory database, you don't need to make a migration when the data model is changed.
                    // Do not use this code in production environment to avoid data loss.
                    // We recommend that you refer to the following help topic before you use an in-memory database: https://docs.microsoft.com/en-us/ef/core/testing/in-memory
                    options.UseInMemoryDatabase();
                    //string connectionString = null;
                    //if(Configuration.GetConnectionString("ConnectionString") != null) {
                    //    connectionString = Configuration.GetConnectionString("ConnectionString");
                    //}
//#if EASYTEST
//                    if(Configuration.GetConnectionString("EasyTestConnectionString") != null) {
//                        connectionString = Configuration.GetConnectionString("EasyTestConnectionString");
//                    }
//#endif
//                    ArgumentNullException.ThrowIfNull(connectionString);
//                    options.UseConnectionString(connectionString);
                })
                .AddNonPersistent();
            builder.Security
                .UseIntegratedMode(options => {
                    options.Lockout.Enabled = true;

                    options.RoleType = typeof(PermissionPolicyRole);
                    // ApplicationUser descends from PermissionPolicyUser and supports the OAuth authentication. For more information, refer to the following topic: https://docs.devexpress.com/eXpressAppFramework/402197
                    // If your application uses PermissionPolicyUser or a custom user type, set the UserType property as follows:
                    options.UserType = typeof(XafKeycloakAuth.Module.BusinessObjects.ApplicationUser);
                    // ApplicationUserLoginInfo is only necessary for applications that use the ApplicationUser user type.
                    // If you use PermissionPolicyUser or a custom user type, comment out the following line:
                    options.UserLoginInfoType = typeof(XafKeycloakAuth.Module.BusinessObjects.ApplicationUserLoginInfo);
                    options.Events.OnSecurityStrategyCreated += securityStrategy => {
                        // Use the 'PermissionsReloadMode.NoCache' option to load the most recent permissions from the database once
                        // for every DbContext instance when secured data is accessed through this instance for the first time.
                        // Use the 'PermissionsReloadMode.CacheOnFirstAccess' option to reduce the number of database queries.
                        // In this case, permission requests are loaded and cached when secured data is accessed for the first time
                        // and used until the current user logs out.
                        // See the following article for more details: https://docs.devexpress.com/eXpressAppFramework/DevExpress.ExpressApp.Security.SecurityStrategy.PermissionsReloadMode.
                        ((SecurityStrategy)securityStrategy).PermissionsReloadMode = PermissionsReloadMode.NoCache;
                    };
                })
                .AddPasswordAuthentication(options => {
                    options.IsSupportChangePassword = true;
                })
                .AddAuthenticationProvider<KeycloakAuthenticationProvider>();
        });
        
        var authentication = services.AddAuthentication(options => {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = "Keycloak";
        });
        
        authentication.AddCookie(options => {
            options.LoginPath = "/LoginPage";
            options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
            options.SlidingExpiration = true;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.Cookie.HttpOnly = true;
        });
        
        // Add Keycloak OpenID Connect authentication
        authentication.AddOpenIdConnect("Keycloak", "Keycloak", options => {
            var keycloakConfig = Configuration.GetSection("Authentication:Keycloak");
            
            options.Authority = keycloakConfig["Authority"];
            options.ClientId = keycloakConfig["ClientId"];
            options.ClientSecret = keycloakConfig["ClientSecret"];
            options.RequireHttpsMetadata = bool.Parse(keycloakConfig["RequireHttpsMetadata"] ?? "false");
            options.ResponseType = keycloakConfig["ResponseType"];
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");
            options.CallbackPath = keycloakConfig["CallbackPath"];
            options.SignedOutCallbackPath = keycloakConfig["SignedOutCallbackPath"];
            options.GetClaimsFromUserInfoEndpoint = bool.Parse(keycloakConfig["GetClaimsFromUserInfoEndpoint"] ?? "true");
            options.SaveTokens = bool.Parse(keycloakConfig["SaveTokens"] ?? "true");
            options.UsePkce = bool.Parse(keycloakConfig["UsePkce"] ?? "false");
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            
            options.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = context =>
                {
                    // Customize the redirect to Keycloak if needed
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                    logger.LogInformation("Redirecting to Keycloak for authentication");
                    return Task.CompletedTask;
                },
                OnRedirectToIdentityProviderForSignOut = context =>
                {
                    // Handle logout redirect to Keycloak
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                    logger.LogInformation("Redirecting to Keycloak for logout");
                    return Task.CompletedTask;
                },
                OnSignedOutCallbackRedirect = context =>
                {
                    // Handle post-logout callback from Keycloak
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                    logger.LogInformation("Keycloak logout completed, redirecting to home");
                    context.Response.Redirect("/");
                    context.HandleResponse();
                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = context =>
                {
                    // Log authentication failures with more detail
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                    logger.LogError(context.Exception, "Keycloak authentication failed. Exception: {ExceptionMessage}", context.Exception?.Message);
                    
                    // Handle state protection errors specifically
                    if (context.Exception?.Message?.Contains("Unable to unprotect") == true)
                    {
                        logger.LogWarning("State protection error - clearing authentication and redirecting to start fresh");
                        context.Response.Redirect("/Authentication/Login");
                        context.HandleResponse();
                    }
                    
                    return Task.CompletedTask;
                },
                OnTokenValidated = context =>
                {
                    // Token has been validated, user will be redirected back
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                    logger.LogInformation("Keycloak token validated for user: {User}", context.Principal?.Identity?.Name);
                    return Task.CompletedTask;
                },
                OnMessageReceived = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                    logger.LogInformation("OpenID Connect message received at {Path}", context.Request.Path);
                    return Task.CompletedTask;
                }
            };
        });
        
        authentication.AddJwtBearer(options => {
            options.TokenValidationParameters = new TokenValidationParameters() {
                ValidateIssuerSigningKey = true,
                //ValidIssuer = Configuration["Authentication:Jwt:Issuer"],
                //ValidAudience = Configuration["Authentication:Jwt:Audience"],
                ValidateIssuer = false,
                ValidateAudience = false,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Authentication:Jwt:IssuerSigningKey"])),
                AuthenticationType = JwtBearerDefaults.AuthenticationScheme
            };
        });
        
        services.AddAuthorization(options => {
            options.DefaultPolicy = new AuthorizationPolicyBuilder(
                JwtBearerDefaults.AuthenticationScheme)
                    .RequireAuthenticatedUser()
                    .RequireXafAuthentication()
                    .Build();
        });

        services
            .AddControllers()
            .AddOData((options, serviceProvider) => {
                options
                    .AddRouteComponents("api/odata", new EdmModelBuilder(serviceProvider).GetEdmModel(), Microsoft.OData.ODataVersion.V401, _routeServices => {
                        _routeServices.ConfigureXafWebApiServices();
                    })
                    .EnableQueryFeatures(100);
            });

        services.AddSwaggerGen(c => {
            c.EnableAnnotations();
            c.SwaggerDoc("v1", new OpenApiInfo {
                Title = "XafKeycloakAuth API",
                Version = "v1",
                Description = @"Use AddXafWebApi(options) in the XafKeycloakAuth.Blazor.Server\Startup.cs file to make Business Objects available in the Web API."
            });
            c.AddSecurityDefinition("JWT", new OpenApiSecurityScheme() {
                Type = SecuritySchemeType.Http,
                Name = "Bearer",
                Scheme = "bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header
            });
            c.AddSecurityRequirement(new OpenApiSecurityRequirement() {
                {
                    new OpenApiSecurityScheme() {
                        Reference = new OpenApiReference() {
                            Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                            Id = "JWT"
                        }
                    },
                    new string[0]
                },
            });
        });

        services.Configure<Microsoft.AspNetCore.Mvc.JsonOptions>(o => {
            //The code below specifies that the naming of properties in an object serialized to JSON must always exactly match
            //the property names within the corresponding CLR type so that the property names are displayed correctly in the Swagger UI.
            //XPO is case-sensitive and requires this setting so that the example request data displayed by Swagger is always valid.
            //Comment this code out to revert to the default behavior.
            //See the following article for more information: https://learn.microsoft.com/en-us/dotnet/api/system.text.json.jsonserializeroptions.propertynamingpolicy
            o.JsonSerializerOptions.PropertyNamingPolicy = null;
        });
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
        if(env.IsDevelopment()) {
            app.UseDeveloperExceptionPage();
            app.UseSwagger();
            app.UseSwaggerUI(c => {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "XafKeycloakAuth WebApi v1");
            });
        }
        else {
            app.UseExceptionHandler("/Error");
            // The default HSTS value is 30 days. To change this for production scenarios, see: https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }
        app.UseHttpsRedirection();
        app.UseRequestLocalization();
        app.UseStaticFiles();
        app.UseRouting();
        app.UseSession();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();
        app.UseXaf();
        // Add Keycloak to XAF bridge middleware AFTER XAF initialization (like LoginExample)
        app.UseMiddleware<KeycloakXafBridgeMiddleware>();
        app.UseEndpoints(endpoints => {
            endpoints.MapXafEndpoints();
            endpoints.MapBlazorHub();
            endpoints.MapFallbackToPage("/_Host");
            endpoints.MapControllers();
        });
    }
}
