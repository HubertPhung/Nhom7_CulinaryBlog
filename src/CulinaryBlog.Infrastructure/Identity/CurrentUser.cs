namespace CulinaryBlog.Infrastructure.Identity;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using CulinaryBlog.Application.Abstractions.Identity;
using CulinaryBlog.Application.Auth.Common;
using Microsoft.AspNetCore.Http;

public sealed class CurrentUser(IHttpContextAccessor httpContextAccessor) : ICurrentUser
{
    public string? UserId =>
        httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? httpContextAccessor.HttpContext?.User.FindFirstValue(JwtRegisteredClaimNames.Sub);

    public string? Email =>
        httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.Email)
        ?? httpContextAccessor.HttpContext?.User.FindFirstValue(JwtRegisteredClaimNames.Email);

    public bool IsAuthenticated =>
        httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated ?? false;

    public bool IsInRole(string role) =>
        httpContextAccessor.HttpContext?.User.IsInRole(role) ?? false;

    public IReadOnlyList<string> Roles =>
        httpContextAccessor.HttpContext?.User.FindAll(c => c.Type is ClaimTypes.Role or "role" or "roles")
            .Select(c => c.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList() ?? [];

    public bool IsAdmin => IsInRole(CulinaryBlog.Application.Auth.Common.Roles.Admin);

    public bool IsAuthor => IsInRole(CulinaryBlog.Application.Auth.Common.Roles.Author);
}
