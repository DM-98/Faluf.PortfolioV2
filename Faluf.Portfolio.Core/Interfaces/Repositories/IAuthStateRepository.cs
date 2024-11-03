using Faluf.Portfolio.Core.Domain;

namespace Faluf.Portfolio.Core.Interfaces.Repositories;

public interface IAuthStateRepository : IBaseRepository<AuthState>
{
    Task<AuthState?> GetByRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);

    Task<AuthState?> GetByUserIdAndClientTypeAsync(Guid id, ClientType clientType, CancellationToken cancellationToken = default);
}