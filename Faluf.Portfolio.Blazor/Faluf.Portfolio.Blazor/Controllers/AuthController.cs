using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

namespace Faluf.Portfolio.Blazor.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AuthController(IAuthService authService, IDataProtectionProvider dataProtectionProvider) : ControllerBase
{
	[HttpPost("Login")]
    public async Task<ActionResult<Result<TokenDTO>>> LoginAsync(LoginInputModel loginInputModel, CancellationToken cancellationToken = default)
    {
        Result<TokenDTO> result = await authService.LoginAsync(loginInputModel, cancellationToken);

        if (result.IsSuccess)
        {
			CookieOptions cookieOptions = new()
			{
				IsEssential = true,
				HttpOnly = true,
				Secure = true,
				SameSite = SameSiteMode.Strict,
				Expires = loginInputModel.IsPersistent ? DateTimeOffset.UtcNow.AddYears(1) : default
			};

			IDataProtector dataProtector = dataProtectionProvider.CreateProtector(Globals.AuthProtector);

			Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(result.Content.AccessToken), cookieOptions);
			Response.Cookies.Append(Globals.IsPersistent, dataProtector.Protect(loginInputModel.IsPersistent.ToString()), cookieOptions);
		}

		return StatusCode((int)result.StatusCode, result);
    }

	[HttpPost("RefreshTokens")]
	public async Task<ActionResult<Result<TokenDTO>>> RefreshTokensAsync(RefreshTokenInputModel refreshTokenInputModel, CancellationToken cancellationToken = default)
    {
		Result<TokenDTO> result = await authService.RefreshTokensAsync(refreshTokenInputModel, cancellationToken);

		return StatusCode((int)result.StatusCode, result);
    }

    [HttpPost("Logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete(Globals.AccessToken);
        Response.Cookies.Delete(Globals.IsPersistent);

        return LocalRedirect("/");
    }
}