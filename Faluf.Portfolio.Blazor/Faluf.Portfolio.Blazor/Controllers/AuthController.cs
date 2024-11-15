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

	public record RefreshTokenRequest(string RefreshToken);

	[HttpPost("RefreshTokens")]
	public async Task<ActionResult<Result<TokenDTO>>> RefreshTokensAsync([FromBody] RefreshTokenRequest refreshTokenRequest, CancellationToken cancellationToken = default)
    {
		Result<TokenDTO> result = await authService.RefreshTokensAsync(refreshTokenRequest.RefreshToken, cancellationToken);

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