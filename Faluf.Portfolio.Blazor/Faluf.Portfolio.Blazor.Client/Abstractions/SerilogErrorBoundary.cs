using Microsoft.AspNetCore.Components.Web;

namespace Faluf.Portfolio.Blazor.Client.Abstractions;

public sealed class SerilogErrorBoundary(ILogger<SerilogErrorBoundary> logger) : ErrorBoundary
{
    protected override async Task OnErrorAsync(Exception exception)
    {
        logger.LogError(exception, "An error occurred in the application");

        await Task.CompletedTask;
    }
}