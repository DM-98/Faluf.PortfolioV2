using Microsoft.AspNetCore.DataProtection;

namespace Faluf.Portfolio.Blazor.Middlewares;

public sealed class CookieAuthMiddleware(RequestDelegate next, IDataProtectionProvider dataProtectionProvider)
{
    private readonly IDataProtector dataProtector = dataProtectionProvider.CreateProtector(Globals.AuthProtector);

    public Task InvokeAsync(HttpContext context)
    {
        if (CookieLoginHelper.CookieLoginQueue.TryDequeue(out (TokenDTO TokenDTO, bool IsPersisted) loginQueue))
        {
            CookieOptions cookieOptions = new()
            {
				IsEssential = true,
                HttpOnly = true,
				Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = loginQueue.IsPersisted ? DateTimeOffset.UtcNow.AddYears(1) : null
            };

            context.Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(loginQueue.TokenDTO.AccessToken), cookieOptions);
            context.Response.Cookies.Append(Globals.IsPersistent, dataProtector.Protect(loginQueue.IsPersisted.ToString()), cookieOptions);
        }

		if (CookieLoginHelper.CookieRefreshTokensQueue.TryDequeue(out TokenDTO? refreshTokenQueue))
		{
			bool isPersisted = context.Request.Cookies[Globals.IsPersistent] is { } isPersistedString && Convert.ToBoolean(dataProtector.Unprotect(isPersistedString));

			CookieOptions cookieOptions = new()
			{
				IsEssential = true,
				HttpOnly = true,
				Secure = true,
				SameSite = SameSiteMode.Lax,
				Expires = isPersisted ? DateTimeOffset.UtcNow.AddYears(1) : null
			};

			context.Response.Cookies.Append(Globals.RefreshToken, dataProtector.Protect(refreshTokenQueue.AccessToken), cookieOptions);
            context.Response.Cookies.Append(Globals.IsPersistent, dataProtector.Protect(isPersisted.ToString()), cookieOptions);
		}

        return next(context);
    }
}

public static class CookieAuthMiddlewareExtensions
{
    public static IApplicationBuilder UseCookieAuthMiddleware(this IApplicationBuilder builder) => builder.UseMiddleware<CookieAuthMiddleware>();
}