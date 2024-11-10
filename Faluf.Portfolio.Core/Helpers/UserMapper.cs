namespace Faluf.Portfolio.Core.Helpers;

public static class UserMapper
{
    public static User ToUser(this RegisterInputModel registerInputModel)
    {
        return new User
        {
            Username = registerInputModel.Username,
            Email = registerInputModel.Email,
            Roles = ["User"],
            TermsAcceptedAt = DateTimeOffset.UtcNow,
        };
    }
}