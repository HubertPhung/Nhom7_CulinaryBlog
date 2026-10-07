namespace CulinaryBlog.Application.Tests.Auth;

using CulinaryBlog.Application.Abstractions.Identity;
using CulinaryBlog.Application.Auth.Services;
using CulinaryBlog.Application.Common.Exceptions;
using CulinaryBlog.Domain.Recipes;

public sealed class RecipeAuthorizationServiceTests
{
    private const string OwnerId = "author-owner-123";
    private const string OtherAuthorId = "author-other-456";
    private const string AdminId = "admin-789";

    [Fact]
    public void CanManageWhenAnonymousReturnsFalse()
    {
        var currentUser = new FakeCurrentUser(userId: null, isAuthenticated: false);
        var service = new RecipeAuthorizationService(currentUser);

        var canManage = service.CanManage(OwnerId);

        Assert.False(canManage);
    }

    [Fact]
    public void CanManageWhenNonOwnerAuthorReturnsFalse()
    {
        var currentUser = new FakeCurrentUser(userId: OtherAuthorId, isAuthenticated: true, roles: ["Author"]);
        var service = new RecipeAuthorizationService(currentUser);

        var canManage = service.CanManage(OwnerId);

        Assert.False(canManage);
    }

    [Fact]
    public void CanManageWhenOwnerAuthorReturnsTrue()
    {
        var currentUser = new FakeCurrentUser(userId: OwnerId, isAuthenticated: true, roles: ["Author"]);
        var service = new RecipeAuthorizationService(currentUser);

        var canManage = service.CanManage(OwnerId);

        Assert.True(canManage);
    }

    [Fact]
    public void CanManageWhenAdminUserReturnsTrueEvenIfNotOwner()
    {
        var currentUser = new FakeCurrentUser(userId: AdminId, isAuthenticated: true, roles: ["Admin", "Author"]);
        var service = new RecipeAuthorizationService(currentUser);

        var canManage = service.CanManage(OwnerId);

        Assert.True(canManage);
    }

    [Fact]
    public void EnsureCanManageWhenAnonymousThrowsUnauthorizedException()
    {
        var currentUser = new FakeCurrentUser(userId: null, isAuthenticated: false);
        var service = new RecipeAuthorizationService(currentUser);

        var exception = Assert.Throws<UnauthorizedException>(() => service.EnsureCanManage(OwnerId));

        Assert.Equal("UNAUTHORIZED", exception.Code);
    }

    [Fact]
    public void EnsureCanManageWhenNonOwnerAuthorThrowsForbiddenExceptionWithRecipeForbiddenCode()
    {
        var currentUser = new FakeCurrentUser(userId: OtherAuthorId, isAuthenticated: true, roles: ["Author"]);
        var service = new RecipeAuthorizationService(currentUser);

        var exception = Assert.Throws<ForbiddenException>(() => service.EnsureCanManage(OwnerId));

        Assert.Equal("RECIPE_FORBIDDEN", exception.Code);
    }

    [Fact]
    public void EnsureCanManageWhenOwnerAuthorDoesNotThrow()
    {
        var currentUser = new FakeCurrentUser(userId: OwnerId, isAuthenticated: true, roles: ["Author"]);
        var service = new RecipeAuthorizationService(currentUser);

        var exception = Record.Exception(() => service.EnsureCanManage(OwnerId));

        Assert.Null(exception);
    }

    [Fact]
    public void EnsureCanManageWhenAdminUserDoesNotThrowEvenIfNotOwner()
    {
        var currentUser = new FakeCurrentUser(userId: AdminId, isAuthenticated: true, roles: ["Admin"]);
        var service = new RecipeAuthorizationService(currentUser);

        var exception = Record.Exception(() => service.EnsureCanManage(OwnerId));

        Assert.Null(exception);
    }

    [Fact]
    public void EnsureCanManageWithRecipeEntityWhenNonOwnerThrowsForbiddenException()
    {
        var currentUser = new FakeCurrentUser(userId: OtherAuthorId, isAuthenticated: true, roles: ["Author"]);
        var service = new RecipeAuthorizationService(currentUser);
        var recipe = CreateRecipeWithAuthor(OwnerId);

        var exception = Assert.Throws<ForbiddenException>(() => service.EnsureCanManage(recipe));

        Assert.Equal("RECIPE_FORBIDDEN", exception.Code);
    }

    [Fact]
    public void EnsureCanManageWithRecipeEntityWhenOwnerDoesNotThrow()
    {
        var currentUser = new FakeCurrentUser(userId: OwnerId, isAuthenticated: true, roles: ["Author"]);
        var service = new RecipeAuthorizationService(currentUser);
        var recipe = CreateRecipeWithAuthor(OwnerId);

        var exception = Record.Exception(() => service.EnsureCanManage(recipe));

        Assert.Null(exception);
    }

    [Fact]
    public void EnsureCanManageWithRecipeEntityWhenAdminDoesNotThrow()
    {
        var currentUser = new FakeCurrentUser(userId: AdminId, isAuthenticated: true, roles: ["Admin"]);
        var service = new RecipeAuthorizationService(currentUser);
        var recipe = CreateRecipeWithAuthor(OwnerId);

        var exception = Record.Exception(() => service.EnsureCanManage(recipe));

        Assert.Null(exception);
    }

    private static Recipe CreateRecipeWithAuthor(string authorId)
    {
        return Recipe.Create(
            "Delicious Pasta",
            "delicious-pasta",
            "A test recipe description",
            Guid.NewGuid(),
            authorId,
            15,
            30,
            4,
            RecipeDifficulty.Medium);
    }

    private sealed class FakeCurrentUser(
        string? userId,
        bool isAuthenticated,
        string[]? roles = null,
        string? email = "user@culinary.test") : ICurrentUser
    {
        public string? UserId => userId;
        public string? Email => email;
        public bool IsAuthenticated => isAuthenticated;
        public IReadOnlyList<string> Roles => roles ?? [];
        public bool IsAdmin => IsInRole("Admin");
        public bool IsAuthor => IsInRole("Author");

        public bool IsInRole(string role) =>
            roles?.Contains(role, StringComparer.OrdinalIgnoreCase) ?? false;
    }
}
