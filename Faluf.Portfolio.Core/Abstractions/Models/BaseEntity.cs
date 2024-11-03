using System.ComponentModel.DataAnnotations;

namespace Faluf.Portfolio.Core.Abstractions.Models;

public abstract class BaseEntity : ISoftDeletable
{
    [Key]
    public Guid Id { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    public DateTime? DeletedAt { get; set; }
}