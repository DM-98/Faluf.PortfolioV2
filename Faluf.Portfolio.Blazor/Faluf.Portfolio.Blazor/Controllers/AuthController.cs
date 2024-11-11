using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace Faluf.Portfolio.Blazor.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AuthController(CookieContainer cookieContainer, IAuthService authService, IDataProtectionProvider dataProtectionProvider) : ControllerBase
{
	private readonly IDataProtector dataProtector = dataProtectionProvider.CreateProtector(Globals.AuthProtector);

	[HttpPost("Login")]
    public async Task<ActionResult<Result<TokenDTO>>> LoginAsync(LoginInputModel loginInputModel, CancellationToken cancellationToken = default)
    {
        Result<TokenDTO> result = await authService.LoginAsync(loginInputModel, cancellationToken);

		if (result.IsSuccess)
		{
			SetCookies(loginInputModel.IsPersistent, result.Content);
		}

		return StatusCode((int)result.StatusCode, result);
    }

    [HttpPost("RefreshTokens")]
	public async Task<ActionResult<Result<TokenDTO>>> RefreshTokensAsync(TokenDTO tokenDTO, CancellationToken cancellationToken = default)
    {
        Result<TokenDTO> result = await authService.RefreshTokensAsync(tokenDTO, cancellationToken);

		if (result.IsSuccess)
		{
			bool isPersistent = Request.Cookies[Globals.IsPersistent] is { } isPersistentString && Convert.ToBoolean(dataProtector.Unprotect(isPersistentString));

			SetCookies(isPersistent, result.Content);
		}

		return StatusCode((int)result.StatusCode, result);
    }

    [HttpPost("Logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete(Globals.AccessToken);
        Response.Cookies.Delete(Globals.IsPersistent);

        return Ok();
    }

	private void SetCookies(bool isPersistent, TokenDTO tokenDTO)
	{
		CookieOptions cookieOptions = new()
		{
			IsEssential = true,
			HttpOnly = true,
			Secure = true,
			SameSite = SameSiteMode.Lax,
			Expires = isPersistent ? DateTimeOffset.UtcNow.AddYears(1) : null
		};

		Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(tokenDTO.AccessToken), cookieOptions);
		Response.Cookies.Append(Globals.IsPersistent, dataProtector.Protect(isPersistent.ToString()), cookieOptions);

		cookieContainer.Add(new Uri($"{Request.Scheme}://{Request.Host}"), new Cookie(Globals.AccessToken, dataProtector.Protect(tokenDTO.AccessToken)));
		cookieContainer.Add(new Uri($"{Request.Scheme}://{Request.Host}"), new Cookie(Globals.IsPersistent, dataProtector.Protect(isPersistent.ToString())));
	}
}