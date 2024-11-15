namespace Faluf.Portfolio.Blazor.Services;

public sealed class TokenService
{
	public HttpContext? HttpContext { get; set; }

	public event Action<TokenDTO?>? TokensRefreshed;
	private TokenDTO? currentTokens;

	public TokenDTO? CurrentTokens
	{
		get => currentTokens;
		set
		{
			currentTokens = value;

			TokensRefreshed?.Invoke(currentTokens);
		}
	}
}