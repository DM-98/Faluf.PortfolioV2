using Microsoft.AspNetCore.Components;

namespace Faluf.Portfolio.Blazor.Abstractions;

public abstract class ExtendedComponentBase : ComponentBase
{
    public virtual bool IsLoading { get; set; }
    public virtual string? ErrorMessage { get; set; }

    public CancellationToken CancellationToken => cancellationTokenSource.Token;
    
    private CancellationTokenSource cancellationTokenSource = new();

    public void Cancel()
    {
        CancellationTokenSource newCts = new();
        CancellationTokenSource oldToken = Interlocked.Exchange(ref cancellationTokenSource, newCts);

        oldToken.Cancel();
        oldToken.Dispose();

        ErrorMessage = null;
        IsLoading = false;
    }

    public void SetErrorMessage(string message) => ErrorMessage = message;

    public void SetErrorMessage<T>(Result<T> result)
    {
        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
        {
            ErrorMessage += "<b>Error:</b><br />" + (!string.IsNullOrWhiteSpace(result.ErrorMessage) ? result.ErrorMessage : "---");
            ErrorMessage += "<br />";
            ErrorMessage += "<br />";
            ErrorMessage += "<b>Exception:</b><br />" + (!string.IsNullOrWhiteSpace(result.ExceptionMessage) ? result.ExceptionMessage : "---");
            ErrorMessage += "<br />";
            ErrorMessage += "<br />";
            ErrorMessage += "<b>Inner exception:</b><br />" + (!string.IsNullOrWhiteSpace(result.InnerExceptionMessage) ? result.InnerExceptionMessage : "---");
            ErrorMessage += "<br />";
            ErrorMessage += "<br />";
            ErrorMessage += "<b>Stack trace:</b><br />" + (!string.IsNullOrWhiteSpace(result.StackTrace) ? result.StackTrace : "---");
        }
        else
        {
            ErrorMessage = $"{result.ErrorMessage} ({(int)result.StatusCode})";
        }
    }
}