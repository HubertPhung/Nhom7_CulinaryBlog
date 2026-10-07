namespace CulinaryBlog.Application.Auth.Services;

using CulinaryBlog.Application.Abstractions.Identity;
using CulinaryBlog.Application.Common.Exceptions;
using CulinaryBlog.Domain.Recipes;

public sealed class RecipeAuthorizationService(ICurrentUser currentUser) : IRecipeAuthorizationService
{
    public bool CanManage(Recipe recipe)
    {
        ArgumentNullException.ThrowIfNull(recipe);
        return CanManage(recipe.AuthorId);
    }

    public bool CanManage(string recipeAuthorId)
    {
        if (!currentUser.IsAuthenticated)
        {
            return false;
        }

        if (currentUser.IsAdmin)
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(currentUser.UserId)
            && string.Equals(currentUser.UserId, recipeAuthorId, StringComparison.OrdinalIgnoreCase);
    }

    public void EnsureCanManage(Recipe recipe)
    {
        ArgumentNullException.ThrowIfNull(recipe);
        EnsureCanManage(recipe.AuthorId);
    }

    public void EnsureCanManage(string recipeAuthorId)
    {
        if (!currentUser.IsAuthenticated)
        {
            throw new UnauthorizedException("Người dùng chưa được xác thực.", "UNAUTHORIZED");
        }

        if (currentUser.IsAdmin)
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(currentUser.UserId)
            && string.Equals(currentUser.UserId, recipeAuthorId, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new ForbiddenException("Bạn không có quyền thực hiện thao tác trên công thức này.", "RECIPE_FORBIDDEN");
    }
}

