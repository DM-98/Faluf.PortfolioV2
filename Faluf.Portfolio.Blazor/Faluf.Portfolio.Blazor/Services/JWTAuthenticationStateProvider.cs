using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;

namespace Faluf.Portfolio.Blazor.Services;

public sealed class JWTAuthenticationStateProvider(IAuthService authService) : ServerAuthenticationStateProvider
{
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        Result<IEnumerable<Claim>> result = await authService.GetCurrentClaimsAsync();

        // No claims, return unauthenticated
        if (!result.IsSuccess)
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        // Check the "exp" claim type, and check if it is NOT expired
        if (long.Parse(result.Content.First(x => x.Type is JwtRegisteredClaimNames.Exp).Value) > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(result.Content, "jwt")));
        }

        // AccessToken is expired, refresh it
        result = await authService.RefreshTokensAsync();

        // Returns either an authenticated or unauthenticated state depending on if refresh call was success or not
        return new AuthenticationState(new ClaimsPrincipal(result.IsSuccess ? new ClaimsIdentity(result.Content, "jwt") : new ClaimsIdentity()));
    }
}