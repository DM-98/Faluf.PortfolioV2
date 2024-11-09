namespace Faluf.Portfolio.Core.Interfaces.Services;

public interface IUserService
{
    Task<Result<User>> RegisterAsync(RegisterInputModel registerInputModel, CancellationToken cancellationToken = default);
}