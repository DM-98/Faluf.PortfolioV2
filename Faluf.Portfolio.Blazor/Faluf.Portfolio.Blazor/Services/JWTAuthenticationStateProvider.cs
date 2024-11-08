using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.DataProtection;

namespace Faluf.Portfolio.Blazor.Services;

public sealed class JWTAuthenticationStateProvider(IDataProtectionProvider dataProtectionProvider, IHttpContextAccessor httpContextAccessor, IAuthService authService) : ServerAuthenticationStateProvider
{
	private readonly IDataProtector dataProtector = dataProtectionProvider.CreateProtector(Globals.AuthProtector);
	private readonly HttpContext httpContext = httpContextAccessor.HttpContext!;

	public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        string? accessToken = httpContext.Request.Cookies[Globals.AccessToken];

		if (accessToken is null)
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        IEnumerable<Claim> claims = new JwtSecurityTokenHandler().ReadJwtToken(dataProtector.Unprotect(accessToken)).Claims;

		if (long.Parse(claims.First(x => x.Type is JwtRegisteredClaimNames.Exp).Value) > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims, Globals.JWTAuthType)));
        }

		Result<TokenDTO> refreshTokensResult = await authService.RefreshTokensAsync(new TokenDTO(accessToken, claims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value));

		if (!refreshTokensResult.IsSuccess)
		{
			httpContext.Response.Cookies.Delete(Globals.AccessToken);
			httpContext.Response.Cookies.Delete(Globals.RememberMe);

			return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
		}

		bool rememberMe = httpContext.Request.Cookies[Globals.RememberMe] is { } rememberMeString && Convert.ToBoolean(dataProtector.Unprotect(rememberMeString));

		CookieOptions cookieOptions = new()
		{
			HttpOnly = true,
			Secure = true,
			SameSite = SameSiteMode.Lax,
			Expires = rememberMe ? DateTimeOffset.UtcNow.AddYears(1) : null
		};

		httpContext.Response.Cookies.Append("accessToken", dataProtector.Protect(accessToken), cookieOptions);
		httpContext.Response.Cookies.Append("rememberMe", dataProtector.Protect(rememberMe.ToString()), cookieOptions);

		return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(new JwtSecurityTokenHandler().ReadJwtToken(refreshTokensResult.Content.AccessToken).Claims, Globals.JWTAuthType)));
    }
}