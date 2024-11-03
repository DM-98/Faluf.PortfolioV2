namespace Faluf.Portfolio.Core.Domain;

public sealed class User : BaseEntity
{
    public string Username { get; set; } = null!;

    public string Email { get; set; } = null!;

    public bool IsEmailConfirmed { get; set; }

    public string HashedPassword { get; set; } = null!;

    public DateTime? TermsAndPrivacyPolicyAcceptedAt { get; set; }

    public List<string> Roles { get; set; } = [];

    public ICollection<Post> Posts { get; set; } = [];
}