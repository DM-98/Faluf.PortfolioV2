using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace Faluf.Portfolio.Blazor.Services;

public sealed class JWTAuthenticationStateProvider(ILoggerFactory loggerFactory, ITokenProvider tokenProvider, IHttpClientFactory httpClientFactory) 
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    private readonly HttpClient httpClient = httpClientFactory.CreateClient(Globals.APIClient);

    protected override TimeSpan RevalidationInterval => TimeSpan.FromSeconds(15);

	protected override async Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken)
	{
		try
		{
			if (long.Parse(authenticationState.User.Claims.First(x => x.Type is JwtRegisteredClaimNames.Exp).Value) > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
			{
				return true;
			}

			HttpResponseMessage httpResponseMessage = await httpClient.PostAsync("Auth/RefreshTokens", new StringContent(JsonSerializer.Serialize(tokenProvider.TokenDTO), Encoding.UTF8, Globals.ApplicationJson), cancellationToken);
			Result<TokenDTO> refreshTokensResult = await httpResponseMessage.Content.ReadFromJsonAsync<Result<TokenDTO>>(cancellationToken) ?? new();

			if (refreshTokensResult.IsSuccess)
			{
				CookieLoginHelper.CookieRefreshTokensQueue.Enqueue(refreshTokensResult.Content);
			}

			NotifyAuthenticationState(refreshTokensResult.Content);
			
			return refreshTokensResult.IsSuccess;
		}
		catch
		{
			return false;
		}
	}

	public void NotifyAuthenticationState(TokenDTO? tokenDTO)
	{
		tokenProvider.TokenDTO = tokenDTO;

		SetAuthenticationState(Task.FromResult(new AuthenticationState(new ClaimsPrincipal(tokenDTO is not null ? new ClaimsIdentity(new JwtSecurityTokenHandler().ReadJwtToken(tokenDTO.AccessToken).Claims, Globals.JWTAuthType) : new ClaimsIdentity()))));
	}
}