using Faluf.Portfolio.Core.DTOs.Inputs;
using FluentValidation;
using Microsoft.Extensions.Localization;

namespace Faluf.Portfolio.Core.Validators;

public sealed class RegisterValidator : AbstractValidator<RegisterInputModel>
{
    public RegisterValidator(IStringLocalizer<SharedResource> stringLocalizer)
    {
        RuleFor(x => x.Username)
            .NotEmpty()
            .WithMessage(stringLocalizer["UsernameRequired"]);
        RuleFor(x => x.Username)
            .MaximumLength(20)
            .WithMessage(stringLocalizer["UsernameMaximumLength", 20]);
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage(stringLocalizer["EmailRequired"]);
        RuleFor(x => x.Email)
            .EmailAddress()
            .WithMessage(stringLocalizer["EmailInvalid"]);
        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage(stringLocalizer["PasswordRequired"]);
        RuleFor(x => x.Password)
            .MinimumLength(6)
            .WithMessage(stringLocalizer["PasswordMinimumLength"]);
        RuleFor(x => x.ConfirmPassword)
            .Equal(x => x.Password)
            .WithMessage(stringLocalizer["PasswordNotMatch"]);
        RuleFor(x => x.IsTermsAccepted)
            .Equal(true)
            .WithMessage(stringLocalizer["AcceptTerms"]);
    }
}