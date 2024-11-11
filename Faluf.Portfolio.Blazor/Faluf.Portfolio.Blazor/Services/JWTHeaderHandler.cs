using System.Net.Http.Headers;

namespace Faluf.Portfolio.Blazor.Services;

public sealed class JWTHeaderHandler(ITokenProvider tokenProvider) : DelegatingHandler
{
	protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
	{
		if (tokenProvider.TokenDTO is not null)
		{
			request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenProvider.TokenDTO.AccessToken);
		}

		return await base.SendAsync(request, cancellationToken);
	}
}