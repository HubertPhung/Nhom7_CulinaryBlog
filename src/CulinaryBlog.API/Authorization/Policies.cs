namespace CulinaryBlog.API.Authorization;

using CulinaryBlog.Application.Auth.Common;
using Microsoft.AspNetCore.Authorization;

public static class Policies
{
    public const string AuthorPolicy = AuthorizationPolicies.AuthorPolicy;
    public const string AdminPolicy = AuthorizationPolicies.AdminPolicy;
    public const string RequireAuthor = AuthorPolicy;
    public const string RequireAdmin = AdminPolicy;

    public static void ConfigureAuthorization(AuthorizationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.AddPolicy(AuthorPolicy, policy =>
            policy.RequireRole(Roles.Author, Roles.Admin));

        options.AddPolicy(AdminPolicy, policy =>
            policy.RequireRole(Roles.Admin));

        // Legacy compatibility alias if needed
        options.AddPolicy("RequireAuthor", policy =>
            policy.RequireRole(Roles.Author, Roles.Admin));

        options.AddPolicy("RequireAdmin", policy =>
            policy.RequireRole(Roles.Admin));
    }
}
