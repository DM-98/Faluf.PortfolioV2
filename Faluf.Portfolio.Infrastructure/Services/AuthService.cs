using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCryptNext = BCrypt.Net.BCrypt;

namespace Faluf.Portfolio.Infrastructure.Services;

public sealed class AuthService(ILogger<AuthService> logger, IAuthStateRepository authStateRepository, IUserRepository userRepository, IStringLocalizer<AuthService> stringLocalizer, IConfiguration configuration) 
    : IAuthService
{
    private readonly string secret = configuration["JWT:Secret"]!;
    private readonly string issuer = configuration["JWT:Issuer"]!;
    private readonly string audience = configuration["JWT:Audience"]!;
    private readonly int accessTokenExpiryInSeconds = int.Parse(configuration["JWT:AccessTokenExpiryInSeconds"]!);
    private readonly int refreshTokenExpiryInDays = int.Parse(configuration["JWT:RefreshTokenExpiryInDays"]!);
    private readonly int maxFailedLoginCount = int.Parse(configuration["MaxFailedLoginCount"]!);

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
            authState ??= new AuthState { UserId = user.Id, ClientType = loginInputModel.ClientType, IsPersistent = loginInputModel.IsPersistent };

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
            authState.RefreshTokenExpiresAt = DateTimeOffset.UtcNow.AddDays(refreshTokenExpiryInDays);

            await authStateRepository.UpsertAsync(authState, cancellationToken).ConfigureAwait(false);

            List<Claim> claims = 
            [
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.Email, user.Email),
                new(JwtRegisteredClaimNames.Jti, authState.RefreshToken)
            ];

            user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role, role)));

			return Result.Ok(new TokenDTO(GenerateAccessToken(claims), authState.RefreshToken));
        }
        catch (Exception ex)
        {
            logger.LogException(ex);

            return Result.InternalServerError<TokenDTO>(stringLocalizer["InternalServerError"], ex);
        }
    }

    public async Task<Result<TokenDTO>> RefreshTokensAsync(TokenDTO tokenDTO, CancellationToken cancellationToken = default)
    {
		try
        {
            IEnumerable<Claim>? claims = await ValidateAccessTokenAsync(tokenDTO.AccessToken).ConfigureAwait(false);

            if (claims is null)
            {
                return Result.Unauthorized<TokenDTO>(stringLocalizer["Unauthorized1"]);
            }

            AuthState? authState = await authStateRepository.GetByRefreshTokenAsync(claims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value, cancellationToken).ConfigureAwait(false);

            if (authState is null or { RefreshToken: null } || authState.RefreshTokenExpiresAt < DateTimeOffset.UtcNow)
            {
                return Result.Unauthorized<TokenDTO>(stringLocalizer["Unauthorized2"]);
            }

            if (authState.LockoutEndAt > DateTimeOffset.UtcNow)
            {
                TimeSpan lockoutEnd = (authState.LockoutEndAt - DateTimeOffset.UtcNow).Value;
                double lockoutEndMinutes = Math.Ceiling(lockoutEnd.TotalMinutes);
                double lockoutEndSeconds = Math.Ceiling(lockoutEnd.TotalSeconds);

                return Result.Locked<TokenDTO>(stringLocalizer["AccountLocked", lockoutEndMinutes, lockoutEndSeconds]);
            }

            authState.RefreshToken = Guid.NewGuid().ToString();
            authState.RefreshTokenExpiresAt = DateTimeOffset.UtcNow.AddDays(refreshTokenExpiryInDays);

            await authStateRepository.UpsertAsync(authState, cancellationToken).ConfigureAwait(false);

            List<Claim> newClaims =
            [
                ..claims.Where(x => x.Type is not JwtRegisteredClaimNames.Jti),
                new(JwtRegisteredClaimNames.Jti, authState.RefreshToken)
            ];

			return Result.Ok(new TokenDTO(GenerateAccessToken(newClaims), authState.RefreshToken));
        }
        catch (Exception ex)
        {
            logger.LogException(ex);

            return Result.InternalServerError<TokenDTO>(stringLocalizer["InternalServerError"], ex);
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
            expires: DateTime.UtcNow.AddSeconds(accessTokenExpiryInSeconds), 
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

        if (validationResult.IsValid && validationResult.SecurityToken is JwtSecurityToken jwtSecurityToken)
        {
            return jwtSecurityToken.Claims;
        }

        return null;
    }
}