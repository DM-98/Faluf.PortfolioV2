namespace Faluf.Portfolio.Core.Domain;

public sealed class Post : BaseEntity
{
    public string Title { get; set; } = null!;

    public string Content { get; set; } = null!;

    public DateTime PublishedAt { get; set; }

    public Guid AuthorId { get; set; }
    
    [ForeignKey(nameof(AuthorId))]
    public User Author { get; set; } = null!;
}