using System.Globalization;
using System.Text;
using System.Threading.RateLimiting;
using CulinaryBlog.API.Authorization;
using CulinaryBlog.API.Endpoints;
using CulinaryBlog.API.ErrorHandling;
using CulinaryBlog.API.Middleware;
using CulinaryBlog.API.Observability;
using CulinaryBlog.Application;
using CulinaryBlog.Infrastructure;
using CulinaryBlog.Infrastructure.Persistence.Seeders;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using Serilog;
using Serilog.Formatting.Compact;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, loggerConfiguration) =>
{
    loggerConfiguration
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .Enrich.WithProperty("Application", "CulinaryBlog.API")
        .WriteTo.Console(new RenderedCompactJsonFormatter());

    var seqUrl = context.Configuration["Seq:ServerUrl"];
    if (!string.IsNullOrWhiteSpace(seqUrl))
    {
        loggerConfiguration.WriteTo.Seq(seqUrl, formatProvider: CultureInfo.InvariantCulture);
    }
});

builder.Services
    .AddApplication()
    .AddInfrastructure(builder.Configuration);

var jwtSecretKey = builder.Configuration["Jwt:SecretKey"];

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = !string.IsNullOrWhiteSpace(jwtSecretKey)
            ? new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey))
            : null,
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? "CulinaryBlog.API",
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"] ?? "CulinaryBlog.Web",
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(1),
    };
});

builder.Services.AddAuthorization(Policies.ConfigureAuthorization);
builder.Services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationHandler, RecipeAuthorizationHandler>();

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth-rate-limit", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString()
                ?? httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
            }));
});

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddOpenApi();
builder.Services.AddHealthChecks().AddCheck("self", () => HealthCheckResult.Healthy(), ["live"]);
builder.Services.AddObservability(builder.Configuration);

var app = builder.Build();

app.UseMiddleware<CorrelationIdMiddleware>();
app.UseSerilogRequestLogging();
app.UseExceptionHandler();
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference("/scalar");
}

app.MapApiEndpoints();
app.MapHealthChecks("/health");
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = registration => registration.Tags.Contains("live"),
});
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = registration => !registration.Tags.Contains("live"),
});

try
{
    using var scope = app.Services.CreateScope();
    var seeder = scope.ServiceProvider.GetRequiredService<RoleSeeder>();
    await seeder.SeedAsync();
    if (app.Environment.IsDevelopment())
    {
        await scope.ServiceProvider.GetRequiredService<CategorySeeder>().SeedAsync();
    }
}
catch (Exception ex)
{
    Program.LogSeederWarning(app.Logger, ex);
}

app.Run();

public partial class Program
{
    private static readonly Action<Microsoft.Extensions.Logging.ILogger, Exception?> LogSeederFailed =
        LoggerMessage.Define(LogLevel.Warning, new EventId(8001, "SeederFailed"), "Could not run role seeder at startup.");

    internal static void LogSeederWarning(Microsoft.Extensions.Logging.ILogger logger, Exception ex) =>
        LogSeederFailed(logger, ex);
}
