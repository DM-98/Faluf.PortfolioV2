using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Primitives;

namespace Faluf.Portfolio.Blazor.Middlewares;

public sealed class CookieAuthMiddleware(RequestDelegate next, IDataProtectionProvider dataProtectionProvider)
{
    private readonly IDataProtector dataProtector = dataProtectionProvider.CreateProtector(Globals.AuthProtector);

    public Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments($"/{Globals.ProcessLogin}") && context.Request.Query.TryGetValue(Globals.RefreshToken, out StringValues refreshToken))
        {
            if (AuthService.CookieLoginQueue.TryDequeue(out (TokenDTO TokenDTO, bool IsPersisted) loginQueue))
            {
                if (loginQueue.TokenDTO.RefreshToken == refreshToken)
                {
                    CookieOptions cookieOptions = new()
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Lax,
                        Expires = loginQueue.IsPersisted ? DateTimeOffset.UtcNow.AddYears(1) : null
                    };

                    context.Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(loginQueue.TokenDTO.AccessToken), cookieOptions);
                    context.Response.Cookies.Append(Globals.IsPersistent, dataProtector.Protect(loginQueue.IsPersisted.ToString()), cookieOptions);

                    string? returnUrl = context.Request.Query[Globals.ReturnUrl];

                    context.Response.Redirect(!string.IsNullOrWhiteSpace(returnUrl) ? returnUrl : "/");

                    return Task.CompletedTask;
                }
            }
        }

        return next(context);
    }
}

public static class CookieAuthMiddlewareExtensions
{
    public static IApplicationBuilder UseCookieAuthMiddleware(this IApplicationBuilder builder) => builder.UseMiddleware<CookieAuthMiddleware>();
}