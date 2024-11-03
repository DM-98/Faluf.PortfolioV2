namespace Faluf.Portfolio.Core.DTOs.Inputs;

public sealed class LoginInputModel
{
    public string Email { get; set; } = null!;

    public string Password { get; set; } = null!;

    public bool RememberMe { get; set; }

    public required ClientType ClientType { get; init; }
}