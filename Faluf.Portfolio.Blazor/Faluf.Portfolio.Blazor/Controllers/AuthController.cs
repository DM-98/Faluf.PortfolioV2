using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace Faluf.Portfolio.Blazor.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AuthController(IAuthService authService) : ControllerBase
{
    [HttpPost("Login")]
    public async Task<IActionResult> LoginAsync(LoginInputModel loginInputModel, CancellationToken cancellationToken = default)
    {
        Result<TokenDTO> result = await authService.LoginAsync(loginInputModel, cancellationToken);

        return StatusCode((int)result.StatusCode, result);
    }

    [HttpGet("RefreshTokens")]
    public async Task<IActionResult> RefreshTokensAsync(CancellationToken cancellationToken = default)
    {
        Result<IEnumerable<Claim>> result = await authService.RefreshTokensAsync(cancellationToken);
     
        return StatusCode((int)result.StatusCode, result);
    }

    [HttpGet("GetCurrentClaims")]
    public async Task<IActionResult> GetCurrentClaimsAsync(CancellationToken cancellationToken = default)
    {
        Result<IEnumerable<Claim>> result = await authService.GetCurrentClaimsAsync(cancellationToken);

        return StatusCode((int)result.StatusCode, result);
    }

    [HttpPost("Logout")]
    public IActionResult Logout()
    {
        HttpContext.Response.Cookies.Delete("accessToken");
        HttpContext.Response.Cookies.Delete("rememberMe");

        return LocalRedirect("/");
    }
}