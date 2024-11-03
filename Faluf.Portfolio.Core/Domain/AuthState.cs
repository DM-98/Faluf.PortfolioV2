namespace Faluf.Portfolio.Core.Domain;

public sealed class AuthState : BaseEntity
{
    public Guid UserId { get; init; }

    [ForeignKey(nameof(UserId))]
    public User User { get; init; } = default!;

    public string? RefreshToken { get; set; }

    public DateTimeOffset? RefreshTokentExpiresAt { get; set; }

    public int AccessFailedCount { get; set; }

    public DateTimeOffset? LockoutEndAt { get; set; }

    public required ClientType ClientType { get; init; }
}