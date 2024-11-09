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

        accessToken = dataProtector.Unprotect(accessToken);

        IEnumerable<Claim> claims = new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims;

		if (long.Parse(claims.First(x => x.Type is JwtRegisteredClaimNames.Exp).Value) > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims, Globals.JWTAuthType)));
        }

		Result<TokenDTO> refreshTokensResult = await authService.RefreshTokensAsync(new TokenDTO(accessToken, claims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value));

		if (!refreshTokensResult.IsSuccess)
		{
			return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
		}

        bool isPersistent = httpContext.Request.Cookies[Globals.IsPersistent] is { } isPersistentString && bool.Parse(dataProtector.Unprotect(isPersistentString));

        CookieOptions cookieOptions = new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = isPersistent ? DateTimeOffset.UtcNow.AddYears(1) : null
        };

        httpContext.Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(refreshTokensResult.Content.AccessToken), cookieOptions);
        httpContext.Response.Cookies.Append(Globals.IsPersistent, dataProtector.Protect(isPersistent.ToString()), cookieOptions);

        AuthenticationState authenticationState = new(new ClaimsPrincipal(new ClaimsIdentity(new JwtSecurityTokenHandler().ReadJwtToken(refreshTokensResult.Content.AccessToken).Claims, Globals.JWTAuthType)));

		SetAuthenticationState(Task.FromResult(authenticationState));

		return authenticationState;
    }
}