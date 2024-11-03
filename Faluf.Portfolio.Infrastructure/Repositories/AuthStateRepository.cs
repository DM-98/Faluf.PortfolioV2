using Faluf.Portfolio.Core.Enums;
using Faluf.Portfolio.Infrastructure.Abstractions;
using Faluf.Portfolio.Infrastructure.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Faluf.Portfolio.Infrastructure.Repositories;

public sealed class AuthStateRepository(IDbContextFactory<PortfolioDbContext> dbContextFactory)
    : BaseRepository<AuthState, PortfolioDbContext>(dbContextFactory), IAuthStateRepository
{
    public async Task<AuthState?> GetByRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        await using PortfolioDbContext context = await DbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

        return await context.AuthStates.FirstOrDefaultAsync(x => x.RefreshToken == refreshToken, cancellationToken).ConfigureAwait(false);
    }

    public async Task<AuthState?> GetByUserIdAndClientTypeAsync(Guid id, ClientType clientType, CancellationToken cancellationToken = default)
    {
        await using PortfolioDbContext context = await DbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

        return await context.AuthStates.FirstOrDefaultAsync(x => x.UserId == id && x.ClientType == clientType, cancellationToken).ConfigureAwait(false);
    }
}