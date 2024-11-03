namespace Faluf.Portfolio.Core.DTOs.Inputs;

public sealed class RegisterInputModel
{
    public string Username { get; set; } = null!;

    public string Email { get; set; } = null!;

    public string Password { get; set; } = null!;

    public string ConfirmPassword { get; set; } = null!;

    public bool IsTermsAccepted { get; set; }
}