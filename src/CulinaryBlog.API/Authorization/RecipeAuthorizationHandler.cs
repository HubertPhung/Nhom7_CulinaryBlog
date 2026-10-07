namespace CulinaryBlog.API.Authorization;

using System.Security.Claims;
using CulinaryBlog.Application.Auth.Common;
using CulinaryBlog.Domain.Recipes;
using Microsoft.AspNetCore.Authorization;

public sealed class RecipeOperationRequirement(string name) : IAuthorizationRequirement
{
    public static readonly RecipeOperationRequirement Manage = new("Manage");
    public static readonly RecipeOperationRequirement Edit = new("Edit");
    public static readonly RecipeOperationRequirement Delete = new("Delete");

    public string Name { get; } = name;
}

public sealed class RecipeAuthorizationHandler : AuthorizationHandler<RecipeOperationRequirement, Recipe>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        RecipeOperationRequirement requirement,
        Recipe resource)
    {
        ArgumentNullException.ThrowIfNull(requirement);
        ArgumentNullException.ThrowIfNull(resource);

        if (context.User.IsInRole(Roles.Admin))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? context.User.FindFirstValue("sub");

        if (!string.IsNullOrEmpty(userId) && string.Equals(resource.AuthorId, userId, StringComparison.OrdinalIgnoreCase))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

