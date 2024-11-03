using Faluf.Portfolio.Core.Domain;
using Microsoft.AspNetCore.Mvc;

namespace Faluf.Portfolio.Blazor.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class UserController(IUserService userService) : ControllerBase
{
    [HttpPost("Register")]
    public async Task<ActionResult<Result<User>>> RegisterAsync(RegisterInputModel registerInputModel, CancellationToken cancellationToken)
    {
        Result<User> result = await userService.RegisterAsync(registerInputModel, cancellationToken);

        return StatusCode((int)result.StatusCode, result);
    }
}