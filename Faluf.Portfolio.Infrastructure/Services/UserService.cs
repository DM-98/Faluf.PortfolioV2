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
            bool emailExists = await userRepository.EmailExistsAsync(registerInputModel.Email, cancellationToken).ConfigureAwait(false);

            if (emailExists)
            {
                return Result.Conflict<User>(stringLocalizer["EmailAlreadyExists"]);
            }

            bool usernameExists = await userRepository.UsernameExistsAsync(registerInputModel.Username, cancellationToken).ConfigureAwait(false);

			if (usernameExists)
			{
				return Result.Conflict<User>(stringLocalizer["UsernameAlreadyExists"]);
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