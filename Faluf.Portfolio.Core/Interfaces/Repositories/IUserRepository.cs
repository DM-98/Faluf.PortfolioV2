namespace Faluf.Portfolio.Core.Interfaces.Repositories;

public interface IUserRepository : IBaseRepository<User>
{
    Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);

    Task<bool> UserExistsAsync(string email, string username, CancellationToken cancellationToken = default);
}