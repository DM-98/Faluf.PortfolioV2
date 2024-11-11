using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.DataProtection;

namespace Faluf.Portfolio.Blazor.Services;

public sealed class JWTAuthenticationStateProvider(ILoggerFactory loggerFactory, NavigationManager navigationManager, IDataProtectionProvider dataProtectionProvider, IHttpContextAccessor httpContextAccessor, IAuthService authService) 
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
	private readonly IDataProtector dataProtector = dataProtectionProvider.CreateProtector(Globals.AuthProtector);
    private readonly ILogger<JWTAuthenticationStateProvider> logger = loggerFactory.CreateLogger<JWTAuthenticationStateProvider>();

	protected override TimeSpan RevalidationInterval => TimeSpan.FromSeconds(15);

	protected override async Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken)
	{		
		logger.LogInformation("ValidateAuthState called...");

		if (long.Parse(authenticationState.User.Claims.First(x => x.Type is JwtRegisteredClaimNames.Exp).Value) > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
		{
			logger.LogInformation("AccessToken has not expired yet - using current claims as auth state.");

			return true;
		}

		string? accessToken = httpContextAccessor.HttpContext!.Request.Cookies[Globals.AccessToken];

		if (accessToken is null)
		{
			logger.LogInformation("No access token found");
		
			return false;
		}

		accessToken = dataProtector.Unprotect(accessToken);

		IEnumerable<Claim> claims = new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims;

		logger.LogInformation("AccessToken has expired - calling refresh tokens...");

		Result<TokenDTO> refreshTokensResult = await authService.RefreshTokensAsync(new TokenDTO(accessToken, claims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value), cancellationToken);

		if (!refreshTokensResult.IsSuccess)
		{
			logger.LogInformation("Refreshing tokens failed: {ErrorMessage} | Exception: {ExceptionMessage} | InnerEx: {InnerExceptionMessage}", refreshTokensResult.ErrorMessage, refreshTokensResult.ExceptionMessage, refreshTokensResult.InnerExceptionMessage);

			return false;
		}

		bool isPersistent = httpContextAccessor.HttpContext!.Request.Cookies[Globals.IsPersistent] is { } isPersistentString && bool.Parse(dataProtector.Unprotect(isPersistentString));
		AuthService.CookieLoginQueue.Enqueue((refreshTokensResult.Content, isPersistent));
		string processLoginUrl = $"/{Globals.ProcessLogin}?{Globals.RefreshToken}={refreshTokensResult.Content.RefreshToken}&{Globals.ReturnUrl}={navigationManager.ToBaseRelativePath(navigationManager.Uri)}";
		navigationManager.NavigateTo(processLoginUrl, forceLoad: false);

		return true;
	}

	//public override async Task<AuthenticationState> GetAuthenticationStateAsync()
	//{
	//	logger.LogInformation("GetAuthState called.");

	//	string? accessToken = httpContextAccessor.HttpContext!.Request.Cookies[Globals.AccessToken];

	//	if (accessToken is null)
	//	{
	//		logger.LogInformation("No access token found");

	//		return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
	//	}

	//	accessToken = dataProtector.Unprotect(accessToken);

	//	IEnumerable<Claim> oldClaims = new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims;

	//	if (long.Parse(oldClaims.First(x => x.Type is JwtRegisteredClaimNames.Exp).Value) > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
	//	{
	//		logger.LogInformation("AccessToken has not expired yet - using current claims as auth state.");

	//		return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(oldClaims, Globals.JWTAuthType)));
	//	}

	//	logger.LogInformation("AccessToken has expired - calling refresh tokens...");

	//	Result<TokenDTO> refreshTokensResult = await authService.RefreshTokensAsync(new TokenDTO(accessToken, oldClaims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value));

	//	if (!refreshTokensResult.IsSuccess)
	//	{
	//		logger.LogInformation("Refreshing tokens failed: {ErrorMessage} | Exception: {ExceptionMessage} | InnerEx: {InnerExceptionMessage}", refreshTokensResult.ErrorMessage, refreshTokensResult.ExceptionMessage, refreshTokensResult.InnerExceptionMessage);

	//		httpContextAccessor.HttpContext!.Response.Cookies.Delete(Globals.AccessToken);
	//		httpContextAccessor.HttpContext!.Response.Cookies.Delete(Globals.IsPersistent);

	//		AuthenticationState anonymousAuthenticationState = new(new ClaimsPrincipal(new ClaimsIdentity()));

	//		NotifyAuthenticationStateChanged(Task.FromResult(anonymousAuthenticationState));

	//		return anonymousAuthenticationState;
	//	}

	//	bool isPersistent = httpContextAccessor.HttpContext!.Request.Cookies[Globals.IsPersistent] is { } isPersistentString && bool.Parse(dataProtector.Unprotect(isPersistentString));

	//	CookieOptions cookieOptions = new()
	//	{
	//		HttpOnly = true,
	//		Secure = true,
	//		SameSite = SameSiteMode.Lax,
	//		Expires = isPersistent ? DateTimeOffset.UtcNow.AddYears(1) : null
	//	};

	//	httpContextAccessor.HttpContext!.Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(refreshTokensResult.Content.AccessToken), cookieOptions);
	//	httpContextAccessor.HttpContext!.Response.Cookies.Append(Globals.IsPersistent, dataProtector.Protect(isPersistent.ToString()), cookieOptions);

	//	IEnumerable<Claim> newClaims = new JwtSecurityTokenHandler().ReadJwtToken(refreshTokensResult.Content.AccessToken).Claims;

	//	AuthenticationState authenticationState = new(new ClaimsPrincipal(new ClaimsIdentity(newClaims, Globals.JWTAuthType)));

	//	NotifyAuthenticationStateChanged(Task.FromResult(authenticationState));

	//	logger.LogInformation("Refreshed tokens - Old: {OldRefreshToken} | New: {NewRefreshToken}", oldClaims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value, newClaims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value);

	//	return authenticationState;
	//}
}