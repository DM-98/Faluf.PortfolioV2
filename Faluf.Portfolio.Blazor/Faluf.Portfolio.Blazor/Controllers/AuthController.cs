using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

namespace Faluf.Portfolio.Blazor.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AuthController(IDataProtectionProvider dataProtectionProvider, IAuthService authService) : ControllerBase
{
	private readonly IDataProtector dataProtector = dataProtectionProvider.CreateProtector(Globals.AuthProtector);

	[HttpPost("Login")]
    public async Task<ActionResult<Result<TokenDTO>>> LoginAsync(LoginInputModel loginInputModel, CancellationToken cancellationToken = default)
    {
        Result<TokenDTO> result = await authService.LoginAsync(loginInputModel, cancellationToken);

		if (result.IsSuccess)
		{
			CookieOptions cookieOptions = new()
			{
				HttpOnly = true,
				Secure = true,
				SameSite = SameSiteMode.Lax,
				Expires = loginInputModel.RememberMe ? DateTime.UtcNow.AddMonths(1) : null
			};

			Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(result.Content.AccessToken), cookieOptions);
			Response.Cookies.Append(Globals.RememberMe, loginInputModel.RememberMe.ToString(), cookieOptions);
		}

		return StatusCode((int)result.StatusCode, result);
    }

    [HttpGet("RefreshTokens")]
    public async Task<ActionResult<Result<TokenDTO>>> RefreshTokensAsync(CancellationToken cancellationToken = default)
    {
		// Check the header for the access token [Mobile & External Clients]
		string? accessToken = Request.Headers.Authorization.ToString().Replace("Bearer ", string.Empty);

		// If the access token is not in the header, check the cookies [Web Client]
		accessToken ??= Request.Cookies[Globals.AccessToken] is { } encryptedAccessToken ? dataProtector.Unprotect(encryptedAccessToken) : null;

		if (accessToken is null)
		{
			return Unauthorized();
		}

		Result<TokenDTO> result = await authService.RefreshTokensAsync(new(accessToken, new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value), cancellationToken);

		if (result.IsSuccess)
		{
			CookieOptions cookieOptions = new()
			{
				HttpOnly = true,
				Secure = true,
				SameSite = SameSiteMode.Lax,
				Expires = DateTime.UtcNow.AddMonths(1)
			};

			Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(result.Content.AccessToken), cookieOptions);
		}

		return StatusCode((int)result.StatusCode, result);
    }

    [HttpPost("Logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete(Globals.AccessToken);
        Response.Cookies.Delete(Globals.RememberMe);

        return NoContent();
    }
}