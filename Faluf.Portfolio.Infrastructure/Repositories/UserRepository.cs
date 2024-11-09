using Microsoft.EntityFrameworkCore;

namespace Faluf.Portfolio.Infrastructure.Repositories;

public sealed class UserRepository(IDbContextFactory<PortfolioDbContext> dbContextFactory) 
    : BaseRepository<User, PortfolioDbContext>(dbContextFactory), IUserRepository
{
    public async Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        await using PortfolioDbContext context = await DbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

        return await context.Users.FirstOrDefaultAsync(x => x.Email == email, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> UserExistsAsync(string email, string username, CancellationToken cancellationToken = default)
    {
        await using PortfolioDbContext context = await DbContextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

        return await context.Users.AnyAsync(x => x.Email == email || x.Username == username, cancellationToken).ConfigureAwait(false);
    }
}