using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Faluf.Portfolio.Infrastructure.Contexts;

public sealed class PortfolioDbContext(DbContextOptions<PortfolioDbContext> options) 
    : DbContext(options), IDataProtectionKeyContext
{
    public DbSet<AuthState> AuthStates => Set<AuthState>();

    public DbSet<Post> Posts => Set<Post>();

    public DbSet<User> Users => Set<User>();

    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        foreach (IMutableEntityType mutableEntityType in modelBuilder.Model.GetEntityTypes().Where(x => typeof(ISoftDeletable).IsAssignableFrom(x.ClrType)))
        {
            mutableEntityType.AddSoftDeleteQueryFilter();
        }
    }
}