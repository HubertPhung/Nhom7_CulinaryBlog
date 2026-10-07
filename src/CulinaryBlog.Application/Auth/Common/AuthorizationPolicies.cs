namespace CulinaryBlog.Application.Auth.Common;

public static class AuthorizationPolicies
{
    public const string AuthorPolicy = "AuthorPolicy";
    public const string AdminPolicy = "AdminPolicy";
    public const string RequireAuthor = AuthorPolicy;
    public const string RequireAdmin = AdminPolicy;
}

