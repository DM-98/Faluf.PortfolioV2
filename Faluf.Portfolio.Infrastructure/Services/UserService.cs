using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using BCryptNext = BCrypt.Net.BCrypt;

namespace Faluf.Portfolio.Infrastructure.Services;

public sealed class UserService(ILogger<UserService> logger, IStringLocalizer<UserService> stringLocalizer, IUserRepository userRepository)
    : IUserService
{
    public async Task<Result<User>> RegisterAsync(RegisterInputModel registerInputModel, CancellationToken cancellationToken = default)
    {
        try
        {
            bool userExists = await userRepository.UserExistsAsync(registerInputModel.Email, registerInputModel.Username, cancellationToken).ConfigureAwait(false);

            if (userExists)
            {
                return Result.BadRequest<User>(stringLocalizer["UserAlreadyExists"]);
            }

            User user = registerInputModel.ToUser();
            user.HashedPassword = BCryptNext.HashPassword(registerInputModel.Password);

            user = await userRepository.UpsertAsync(user, cancellationToken).ConfigureAwait(false);

            return Result.Created(user);
        }
        catch (Exception ex)
        {
            logger.LogException(ex);

            return Result.InternalServerError<User>(stringLocalizer["InternalServerError"], ex);
        }
    }
}