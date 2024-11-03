using Microsoft.Extensions.Logging;

namespace Faluf.Portfolio.Infrastructure.Helpers;

public static class LoggerHelper
{
    public static void LogException(this ILogger logger, Exception ex) => logger.LogError(ex, ""); // https://github.com/dotnet/roslyn-analyzers/issues/5626#issuecomment-1001203885
}