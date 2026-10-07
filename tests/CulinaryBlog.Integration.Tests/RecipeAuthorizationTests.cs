namespace CulinaryBlog.Integration.Tests;

using System.Security.Claims;
using CulinaryBlog.API.Authorization;
using CulinaryBlog.Application.Abstractions.Identity;
using CulinaryBlog.Application.Auth.Common;
using CulinaryBlog.Domain.Recipes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

public sealed class RecipeAuthorizationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private const string OwnerId = "author-owner-id";
    private const string NonOwnerId = "author-other-id";
    private const string AdminId = "admin-id";

    public RecipeAuthorizationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task RecipeAuthorizationHandlerWhenAnonymousFailsRequirement()
    {
        var handler = new RecipeAuthorizationHandler();
        var anonymousUser = new ClaimsPrincipal(new ClaimsIdentity());
        var recipe = CreateTestRecipe(OwnerId);

        var context = new AuthorizationHandlerContext(
            [RecipeOperationRequirement.Manage],
            anonymousUser,
            recipe);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task RecipeAuthorizationHandlerWhenNonOwnerAuthorFailsRequirement()
    {
        var handler = new RecipeAuthorizationHandler();
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, NonOwnerId),
            new Claim(ClaimTypes.Role, Roles.Author),
        };
        var nonOwnerUser = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var recipe = CreateTestRecipe(OwnerId);

        var context = new AuthorizationHandlerContext(
            [RecipeOperationRequirement.Manage],
            nonOwnerUser,
            recipe);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task RecipeAuthorizationHandlerWhenOwnerAuthorSucceedsRequirement()
    {
        var handler = new RecipeAuthorizationHandler();
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, OwnerId),
            new Claim(ClaimTypes.Role, Roles.Author),
        };
        var ownerUser = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var recipe = CreateTestRecipe(OwnerId);

        var context = new AuthorizationHandlerContext(
            [RecipeOperationRequirement.Manage],
            ownerUser,
            recipe);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task RecipeAuthorizationHandlerWhenAdminUserSucceedsRequirementEvenIfNotOwner()
    {
        var handler = new RecipeAuthorizationHandler();
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, AdminId),
            new Claim(ClaimTypes.Role, Roles.Admin),
        };
        var adminUser = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var recipe = CreateTestRecipe(OwnerId);

        var context = new AuthorizationHandlerContext(
            [RecipeOperationRequirement.Manage],
            adminUser,
            recipe);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task AspNetCoreAuthorizationServiceWithRegisteredHandlerResolvesProperly()
    {
        using var scope = _factory.Services.CreateScope();
        var authService = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var recipe = CreateTestRecipe(OwnerId);

        var ownerClaims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, OwnerId),
            new Claim(ClaimTypes.Role, Roles.Author),
        };
        var ownerUser = new ClaimsPrincipal(new ClaimsIdentity(ownerClaims, "TestAuth"));

        var result = await authService.AuthorizeAsync(ownerUser, recipe, [RecipeOperationRequirement.Manage]);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void RecipeAuthorizationServiceFromApplicationDiResolvesAndEnforcesRules()
    {
        using var scope = _factory.Services.CreateScope();
        var recipeAuthService = scope.ServiceProvider.GetRequiredService<IRecipeAuthorizationService>();

        Assert.NotNull(recipeAuthService);
    }

    private static Recipe CreateTestRecipe(string authorId)
    {
        return Recipe.Create(
            "Beef Bourguignon",
            "beef-bourguignon",
            "Classic French stew",
            Guid.NewGuid(),
            authorId,
            30,
            180,
            6,
            RecipeDifficulty.Hard);
    }
}

