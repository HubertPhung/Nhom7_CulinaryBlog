namespace CulinaryBlog.Application.Abstractions.Identity;

public interface ICurrentUser
{
    string? UserId { get; }
    string? Email { get; }
    bool IsAuthenticated { get; }
    bool IsInRole(string role);
    IReadOnlyList<string> Roles { get; }
    bool IsAdmin { get; }
    bool IsAuthor { get; }
}
