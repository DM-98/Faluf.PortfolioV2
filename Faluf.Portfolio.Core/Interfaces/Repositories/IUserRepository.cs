using Faluf.Portfolio.Core.Domain;

namespace Faluf.Portfolio.Core.Interfaces.Repositories;

public interface IUserRepository : IBaseRepository<User>
{
    Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);
}