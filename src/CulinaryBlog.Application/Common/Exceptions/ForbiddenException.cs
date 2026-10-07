namespace CulinaryBlog.Application.Common.Exceptions;

public sealed class ForbiddenException : Exception
{
    public string Code { get; }

    public ForbiddenException(string message, string code = "FORBIDDEN")
        : base(message)
    {
        Code = code;
    }
}
