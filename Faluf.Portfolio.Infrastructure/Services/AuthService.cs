using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using BCryptNext = BCrypt.Net.BCrypt;

namespace Faluf.Portfolio.Infrastructure.Services;

public sealed class AuthService(ILogger<AuthService> logger, IDataProtectionProvider dataProtectionProvider, IHttpContextAccessor httpContextAccessor, IAuthStateRepository authStateRepository, IUserRepository userRepository, IStringLocalizer<AuthService> stringLocalizer, IConfiguration configuration) 
    : IAuthService
{
    private readonly string secret = configuration["JWT:Secret"]!;
    private readonly string issuer = configuration["JWT:Issuer"]!;
    private readonly string audience = configuration["JWT:Audience"]!;
    private readonly int accessTokenExpiryInMinutes = int.Parse(configuration["JWT:AccessTokenExpiryInMinutes"]!);
    private readonly int refreshTokenExpiryInDays = int.Parse(configuration["JWT:RefreshTokenExpiryInDays"]!);
    private readonly int maxFailedLoginCount = int.Parse(configuration["MaxFailedLoginCount"]!);
    private readonly HttpContext httpContext = httpContextAccessor.HttpContext!;
    private readonly IDataProtector dataProtector = dataProtectionProvider.CreateProtector(nameof(AuthService));

    public async Task<Result<TokenDTO>> LoginAsync(LoginInputModel loginInputModel, CancellationToken cancellationToken = default)
    {
        try
        {
            User? user = await userRepository.GetByEmailAsync(loginInputModel.Email, cancellationToken).ConfigureAwait(false);

            if (user is null)
            {
                return Result.Unauthorized<TokenDTO>(stringLocalizer["BadCredentials"]);
            }

            AuthState? authState = await authStateRepository.GetByUserIdAndClientTypeAsync(user.Id, loginInputModel.ClientType, cancellationToken).ConfigureAwait(false);
            authState ??= new AuthState { UserId = user.Id, ClientType = loginInputModel.ClientType };

            if (authState.LockoutEndAt > DateTimeOffset.UtcNow)
            {
                TimeSpan lockoutEnd = (authState.LockoutEndAt - DateTimeOffset.UtcNow).Value;
                double lockoutEndMinutes = Math.Ceiling(lockoutEnd.TotalMinutes);
                double lockoutEndSeconds = Math.Ceiling(lockoutEnd.TotalSeconds);

                return Result.Locked<TokenDTO>(stringLocalizer["AccountLocked", lockoutEndMinutes, lockoutEndSeconds]);
            }

            bool isValidPassword = BCryptNext.Verify(loginInputModel.Password, user.HashedPassword);

            if (!isValidPassword)
            {
                if (++authState.AccessFailedCount >= maxFailedLoginCount)
                {
                    authState.LockoutEndAt = DateTimeOffset.UtcNow.AddMinutes(maxFailedLoginCount);
                }

                await authStateRepository.UpsertAsync(authState, cancellationToken).ConfigureAwait(false);

                return Result.Unauthorized<TokenDTO>(stringLocalizer["BadCredentials", authState.AccessFailedCount]);
            }

            authState.AccessFailedCount = 0;
            authState.LockoutEndAt = null;
            authState.RefreshToken = Guid.NewGuid().ToString();
            authState.RefreshTokentExpiresAt = DateTimeOffset.UtcNow.AddDays(refreshTokenExpiryInDays);

            await authStateRepository.UpsertAsync(authState, cancellationToken).ConfigureAwait(false);

            List<Claim> claims = 
            [
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.Email, user.Email),
                new(JwtRegisteredClaimNames.Jti, authState.RefreshToken)
            ];

            user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role, role)));

            string accessToken = GenerateAccessToken(claims);

            CookieOptions cookieOptions = new()
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = loginInputModel.RememberMe ? DateTimeOffset.UtcNow.AddYears(1) : null
            };

            httpContext.Response.Cookies.Append("accessToken", dataProtector.Protect(accessToken), cookieOptions);
            httpContext.Response.Cookies.Append("rememberMe", dataProtector.Protect(loginInputModel.RememberMe.ToString()), cookieOptions);

            return Result.Ok(new TokenDTO(accessToken, authState.RefreshToken));
        }
        catch (Exception ex)
        {
            logger.LogException(ex);

            return Result.InternalServerError<TokenDTO>(stringLocalizer["InternalServerError"], ex);
        }
    }

    public async Task<Result<IEnumerable<Claim>>> RefreshTokensAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            string? accessToken = httpContext.Request.Cookies["accessToken"];

            if (accessToken is null)
            {
                return Result.Unauthorized<IEnumerable<Claim>>(stringLocalizer["Unauthorized"]);
            }

            IEnumerable<Claim>? claims = await ValidateAccessTokenAsync(accessToken).ConfigureAwait(false);

            if (claims is null)
            {
                httpContext.Response.Cookies.Delete("accessToken");
                httpContext.Response.Cookies.Delete("rememberMe");

                return Result.Unauthorized<IEnumerable<Claim>>(stringLocalizer["Unauthorized"]);
            }

            AuthState? authState = await authStateRepository.GetByRefreshTokenAsync(claims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value, cancellationToken).ConfigureAwait(false);

            if (authState is null or { RefreshToken: null } || authState.RefreshTokentExpiresAt < DateTimeOffset.UtcNow)
            {
                httpContext.Response.Cookies.Delete("accessToken");
                httpContext.Response.Cookies.Delete("rememberMe");

                return Result.Unauthorized<IEnumerable<Claim>>(stringLocalizer["Unauthorized"]);
            }

            if (authState.LockoutEndAt > DateTimeOffset.UtcNow)
            {
                TimeSpan lockoutEnd = (authState.LockoutEndAt - DateTimeOffset.UtcNow).Value;
                double lockoutEndMinutes = Math.Ceiling(lockoutEnd.TotalMinutes);
                double lockoutEndSeconds = Math.Ceiling(lockoutEnd.TotalSeconds);

                return Result.Locked<IEnumerable<Claim>>(stringLocalizer["AccountLocked", lockoutEndMinutes, lockoutEndSeconds]);
            }

            authState.RefreshToken = Guid.NewGuid().ToString();
            authState.RefreshTokentExpiresAt = DateTimeOffset.UtcNow.AddDays(refreshTokenExpiryInDays);

            await authStateRepository.UpsertAsync(authState, cancellationToken).ConfigureAwait(false);

            string? rememberMe = httpContext.Request.Cookies["rememberMe"];

            CookieOptions cookieOptions = new()
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = bool.Parse(!string.IsNullOrWhiteSpace(rememberMe) ? dataProtector.Unprotect(rememberMe) : "False") ? DateTimeOffset.UtcNow.AddYears(1) : null
            };

            List<Claim> newClaims =
            [
                ..claims.Where(x => x.Type is not JwtRegisteredClaimNames.Jti),
                new(JwtRegisteredClaimNames.Jti, authState.RefreshToken)
            ];

            string newAccessToken = GenerateAccessToken(newClaims);

            httpContext.Response.Cookies.Append("accessToken", dataProtector.Protect(newAccessToken), cookieOptions);

            return Result.Ok<IEnumerable<Claim>>(newClaims);
        }
        catch (Exception ex)
        {
            logger.LogException(ex);

            return Result.InternalServerError<IEnumerable<Claim>>(stringLocalizer["InternalServerError"], ex);
        }
    }

    public Task<Result<IEnumerable<Claim>>> GetCurrentClaimsAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            string? accessToken = httpContext.Request.Cookies["accessToken"];

            if (accessToken is null)
            {
                return Task.FromResult(Result.Unauthorized<IEnumerable<Claim>>(stringLocalizer["Unauthorized"]));
            }

            return Task.FromResult(Result.Ok(new JwtSecurityTokenHandler().ReadJwtToken(dataProtector.Unprotect(accessToken)).Claims));
        }
        catch (Exception ex)
        {
            logger.LogException(ex);

            return Task.FromResult(Result.InternalServerError<IEnumerable<Claim>>(stringLocalizer["InternalServerError"], ex));
        }
    }

    private string GenerateAccessToken(IEnumerable<Claim> claims)
    {
        SymmetricSecurityKey securityKey = new(Encoding.UTF8.GetBytes(secret));
        SigningCredentials credentials = new(securityKey, SecurityAlgorithms.HmacSha256Signature);
        JwtSecurityToken token = new(
            issuer: issuer, 
            audience: claims.Any(x => x.Type is JwtRegisteredClaimNames.Aud) ? null : audience, 
            claims: claims, 
            expires: DateTime.UtcNow.AddMinutes(accessTokenExpiryInMinutes), 
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private async Task<IEnumerable<Claim>?> ValidateAccessTokenAsync(string accessToken)
    {
        TokenValidationParameters tokenValidationParameters = new()
        {
            ValidateIssuerSigningKey = true,
            ValidateLifetime = false,
            ValidIssuer = issuer,
            ValidAudience = audience,
            ClockSkew = TimeSpan.Zero,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
        };

        TokenValidationResult validationResult = await new JwtSecurityTokenHandler().ValidateTokenAsync(accessToken, tokenValidationParameters);

        if (validationResult.SecurityToken is JwtSecurityToken jwtSecurityToken)
        {
            return jwtSecurityToken.Claims;
        }

        return null;
    }
}