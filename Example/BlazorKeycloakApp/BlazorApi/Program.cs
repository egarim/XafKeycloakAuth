using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Configure Swagger with JWT Bearer authentication
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "Blazor Keycloak API",
        Version = "v1",
        Description = "API for testing Keycloak JWT authentication"
    });

    // Add JWT Bearer authentication to Swagger
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter your JWT token in the format: Bearer {your_token_here}"
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Configure CORS
var corsSettings = builder.Configuration.GetSection("Cors");
var allowedOrigins = corsSettings.GetSection("AllowedOrigins").Get<string[]>() ?? new[] { "*" };

builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultPolicy", policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Configure JWT authentication
var keycloakConfig = builder.Configuration.GetSection("Keycloak");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = keycloakConfig["Authority"];
        options.Audience = keycloakConfig["Audience"];
        options.RequireHttpsMetadata = keycloakConfig.GetValue<bool>("RequireHttpsMetadata");
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true, // Re-enabled - tokens will now include proper audience
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            NameClaimType = "preferred_username",
            RoleClaimType = "roles",
            ClockSkew = TimeSpan.FromMinutes(5)
        };
        
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                // Transform Keycloak roles from realm_access.roles
                var identity = context.Principal?.Identity as ClaimsIdentity;
                if (identity != null)
                {
                    var realmAccessClaim = context.Principal?.FindFirst("realm_access")?.Value;
                    if (!string.IsNullOrEmpty(realmAccessClaim))
                    {
                        try
                        {
                            var realmAccess = System.Text.Json.JsonDocument.Parse(realmAccessClaim);
                            if (realmAccess.RootElement.TryGetProperty("roles", out var roles))
                            {
                                foreach (var role in roles.EnumerateArray())
                                {
                                    var roleValue = role.GetString();
                                    if (!string.IsNullOrEmpty(roleValue))
                                    {
                                        identity.AddClaim(new Claim(ClaimTypes.Role, roleValue));
                                    }
                                }
                            }
                        }
                        catch (System.Text.Json.JsonException)
                        {
                            // Ignore JSON parsing errors
                        }
                    }
                }
                return Task.CompletedTask;
            }
        };
    });

// Configure authorization
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAuthentication", policy =>
        policy.RequireAuthenticatedUser());
    options.AddPolicy("RequireAdmin", policy =>
        policy.RequireRole("admin"));
    options.AddPolicy("RequireUser", policy =>
        policy.RequireRole("user", "admin"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
// Enable Swagger in all environments for testing purposes
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Blazor Keycloak API v1");
    c.RoutePrefix = string.Empty; // Makes Swagger UI available at the root URL
    c.DisplayOperationId();
    c.DisplayRequestDuration();
    c.DocExpansion(Swashbuckle.AspNetCore.SwaggerUI.DocExpansion.List);
});

app.UseHttpsRedirection();
app.UseCors("DefaultPolicy");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
