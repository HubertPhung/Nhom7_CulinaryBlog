namespace CulinaryBlog.Application.Abstractions.Identity;

using CulinaryBlog.Domain.Recipes;

public interface IRecipeAuthorizationService
{
    bool CanManage(Recipe recipe);
    void EnsureCanManage(Recipe recipe);
    bool CanManage(string recipeAuthorId);
    void EnsureCanManage(string recipeAuthorId);
}

