using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace Faluf.Portfolio.Blazor.Services;

public sealed class JWTAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider
{
	protected override TimeSpan RevalidationInterval => TimeSpan.FromSeconds(15);

	private readonly IAuthService authService;
	private readonly TokenService tokenService;
	private readonly ProtectedLocalStorage protectedLocalStorage;
	private readonly ProtectedSessionStorage protectedSessionStorage;

	private AuthenticationState? authenticationState;

	public JWTAuthenticationStateProvider(ProtectedLocalStorage protectedLocalStorage, ProtectedSessionStorage protectedSessionStorage, IAuthService authService, TokenService tokenService, ILoggerFactory loggerFactory) : base(loggerFactory)
	{
		this.protectedSessionStorage = protectedSessionStorage;
		this.protectedLocalStorage = protectedLocalStorage;
		this.authService = authService;
		this.tokenService = tokenService;

		authenticationState = new AuthenticationState(new ClaimsPrincipal(tokenService.CurrentTokens is not null ? new ClaimsIdentity(new JwtSecurityTokenHandler().ReadJwtToken(tokenService.CurrentTokens.AccessToken).Claims, Globals.JWTAuthType) : new ClaimsIdentity()));

		tokenService.TokensRefreshed += async (tokenDTO) => await AuthenticateUserAsync(tokenDTO);
	}

	protected override async Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken)
	{
		if (long.Parse(authenticationState.User.Claims.First(x => x.Type is JwtRegisteredClaimNames.Exp).Value) > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
		{
			await Console.Out.WriteLineAsync("ValidateAuthenticationStateAsync: Token is still valid");

			return true;
		}

		if (tokenService.CurrentTokens is null)
		{
			await Console.Out.WriteLineAsync("ValidateAuthenticationStateAsync: Token is null");

			return false;
		}

		Result<TokenDTO> refreshTokensResult = await authService.RefreshTokensAsync(tokenService.CurrentTokens.RefreshToken, cancellationToken);

		await Console.Out.WriteLineAsync($"ValidateAuthenticationStateAsync: {refreshTokensResult.IsSuccess}");

		tokenService.CurrentTokens = refreshTokensResult.Content;

		return refreshTokensResult.IsSuccess;
	}

	public override async Task<AuthenticationState> GetAuthenticationStateAsync()
	{
		await Console.Out.WriteLineAsync("GetAuthenticationStateAsync");

		return authenticationState ?? new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
	}

	public async Task AuthenticateUserAsync(TokenDTO? tokenDTO)
	{
		authenticationState = new AuthenticationState(new ClaimsPrincipal(tokenDTO is not null ? new ClaimsIdentity(new JwtSecurityTokenHandler().ReadJwtToken(tokenDTO.AccessToken).Claims, Globals.JWTAuthType) : new ClaimsIdentity()));

		if (tokenDTO is not null)
		{
			await protectedLocalStorage.SetAsync(Globals.IsPersistent, tokenDTO.IsPersistent.ToString());

			if (tokenDTO.IsPersistent)
			{
				await protectedLocalStorage.SetAsync(Globals.AccessToken, tokenDTO.AccessToken);
			}
			else
			{
				await protectedSessionStorage.SetAsync(Globals.AccessToken, tokenDTO.AccessToken);
			}
		}
		else
		{
			await protectedLocalStorage.DeleteAsync(Globals.IsPersistent);
			await protectedLocalStorage.DeleteAsync(Globals.AccessToken);
			await protectedSessionStorage.DeleteAsync(Globals.AccessToken);
		}

		SetAuthenticationState(Task.FromResult(authenticationState));
	}
}