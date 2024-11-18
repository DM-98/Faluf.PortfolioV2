using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;

namespace Faluf.Portfolio.Blazor.Services;

public sealed class JWTRevalidatingAuthenticationStateProvider(IServiceScopeFactory serviceScopeFactory, ILoggerFactory loggerFactory)
	: RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
	protected override TimeSpan RevalidationInterval => TimeSpan.FromSeconds(15);

	protected override async Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken)
	{
		await using AsyncServiceScope scope = serviceScopeFactory.CreateAsyncScope();
		IAuthService authService = scope.ServiceProvider.GetRequiredService<IAuthService>();
		ILogger<JWTRevalidatingAuthenticationStateProvider> logger = scope.ServiceProvider.GetRequiredService<ILogger<JWTRevalidatingAuthenticationStateProvider>>();

		return await ValidateAuthStateAsync(authService, authenticationState.User, logger, cancellationToken);
	}

	public static async Task<bool> ValidateAuthStateAsync(IAuthService authService, ClaimsPrincipal claimsPrincipal, ILogger<JWTRevalidatingAuthenticationStateProvider> logger, CancellationToken cancellationToken)
	{
		logger.LogInformation("Validating authentication state");

		if (claimsPrincipal.Identity is null or { IsAuthenticated: false })
		{
			logger.LogInformation("User is not authenticated");

			return false;
		}

		Result refreshTokensResult = await authService.ValidateRefreshTokenAsync(new RefreshTokenInputModel { RefreshToken = claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Jti)! }, cancellationToken);

		logger.LogInformation("Validated refresh token: {Result}", refreshTokensResult.IsSuccess);

		return refreshTokensResult.IsSuccess;
	}
}