namespace CulinaryBlog.Integration.Tests;

using System.Security.Claims;
using CulinaryBlog.Application.Auth.Common;
using CulinaryBlog.Infrastructure.Identity;
using Microsoft.AspNetCore.Http;

public sealed class CurrentUserTests
{
    [Fact]
    public void CurrentUserWhenHttpContextIsNullReturnsDefaultsWithoutThrowing()
    {
        var accessor = new HttpContextAccessor { HttpContext = null };
        var currentUser = new CurrentUser(accessor);

        Assert.Null(currentUser.UserId);
        Assert.Null(currentUser.Email);
        Assert.False(currentUser.IsAuthenticated);
        Assert.Empty(currentUser.Roles);
        Assert.False(currentUser.IsAdmin);
        Assert.False(currentUser.IsAuthor);
    }

    [Fact]
    public void CurrentUserWithAuthorClaimsParsesPropertiesCorrectly()
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "user-42"),
            new Claim(ClaimTypes.Email, "author@culinary.test"),
            new Claim(ClaimTypes.Role, Roles.Author),
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        var httpContext = new DefaultHttpContext { User = principal };
        var accessor = new HttpContextAccessor { HttpContext = httpContext };

        var currentUser = new CurrentUser(accessor);

        Assert.Equal("user-42", currentUser.UserId);
        Assert.Equal("author@culinary.test", currentUser.Email);
        Assert.True(currentUser.IsAuthenticated);
        Assert.Contains(Roles.Author, currentUser.Roles);
        Assert.True(currentUser.IsAuthor);
        Assert.False(currentUser.IsAdmin);
    }

    [Fact]
    public void CurrentUserWithAdminAndAuthorClaimsRecognizesBothRoles()
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "admin-1"),
            new Claim(ClaimTypes.Email, "admin@culinary.test"),
            new Claim(ClaimTypes.Role, Roles.Admin),
            new Claim(ClaimTypes.Role, Roles.Author),
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        var httpContext = new DefaultHttpContext { User = principal };
        var accessor = new HttpContextAccessor { HttpContext = httpContext };

        var currentUser = new CurrentUser(accessor);

        Assert.Equal("admin-1", currentUser.UserId);
        Assert.True(currentUser.IsAuthenticated);
        Assert.True(currentUser.IsAdmin);
        Assert.True(currentUser.IsAuthor);
        Assert.Equal(2, currentUser.Roles.Count);
    }
}

