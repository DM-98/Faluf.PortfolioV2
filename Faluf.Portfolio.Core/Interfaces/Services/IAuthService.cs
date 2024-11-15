namespace Faluf.Portfolio.Core.Interfaces.Services;

public interface IAuthService
{
    Task<Result<TokenDTO>> LoginAsync(LoginInputModel loginInputModel, CancellationToken cancellationToken = default);

	Task<Result<TokenDTO>> RefreshTokensAsync(string refreshToken, CancellationToken cancellationToken = default);
}