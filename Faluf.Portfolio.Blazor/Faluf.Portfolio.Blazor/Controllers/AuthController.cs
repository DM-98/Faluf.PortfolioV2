using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

namespace Faluf.Portfolio.Blazor.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AuthController(JWTAuthenticationStateProvider jwtAuthenticationStateProvider, IDataProtectionProvider dataProtectionProvider, IAuthService authService) : ControllerBase
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
				Expires = loginInputModel.IsPersistent ? DateTime.UtcNow.AddMonths(1) : null
			};

			Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(result.Content.AccessToken), cookieOptions);
			Response.Cookies.Append(Globals.IsPersistent, dataProtector.Protect(loginInputModel.IsPersistent.ToString()), cookieOptions);
		}

		return StatusCode((int)result.StatusCode, result);
    }

    [HttpGet("RefreshTokens")]
    public async Task<ActionResult<Result<TokenDTO>>> RefreshTokensAsync()
    {
		AuthenticationState authState = await jwtAuthenticationStateProvider.GetAuthenticationStateAsync();

		if (authState.User.Identity is not { IsAuthenticated: true })
		{
			return Unauthorized();
		}

		return Ok();
    }

    [HttpPost("Logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete(Globals.AccessToken);
        Response.Cookies.Delete(Globals.IsPersistent);

        return LocalRedirect("/");
    }
}