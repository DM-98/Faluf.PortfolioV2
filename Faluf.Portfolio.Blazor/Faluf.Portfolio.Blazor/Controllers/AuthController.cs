using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace Faluf.Portfolio.Blazor.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AuthController(IAuthService authService) : ControllerBase
{
	[HttpPost("Login")]
    public async Task<ActionResult<Result<TokenDTO>>> LoginAsync(LoginInputModel loginInputModel, CancellationToken cancellationToken = default)
    {
        Result<TokenDTO> result = await authService.LoginAsync(loginInputModel, cancellationToken);

		return StatusCode((int)result.StatusCode, result);
    }

	[HttpPost("RefreshTokens")]
	public async Task<ActionResult<Result<TokenDTO>>> RefreshTokensAsync([FromBody] RefreshTokenInputModel refreshTokenInputModel, CancellationToken cancellationToken = default)
    {
		Result<TokenDTO> result = await authService.RefreshTokensAsync(refreshTokenInputModel, cancellationToken);

		return StatusCode((int)result.StatusCode, result);
    }

    [HttpPost("Logout")]
    public async Task<IActionResult> LogoutAsync()
    {
		await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

		string refererUrl = Request.Headers.Referer.ToString();

		if (Uri.TryCreate(refererUrl, UriKind.Absolute, out var uri))
		{
			string localPath = uri.PathAndQuery;

			return LocalRedirect($"~{localPath}");
		}

		return LocalRedirect("~/");
	}
}