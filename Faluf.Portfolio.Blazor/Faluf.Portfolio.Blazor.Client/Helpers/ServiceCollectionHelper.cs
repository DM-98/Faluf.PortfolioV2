using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Serilog;
using Serilog.Events;

namespace Faluf.Portfolio.Blazor.Client.Helpers;

internal static class ServiceCollectionHelper
{
    public static void AddPortfolioCore(this WebAssemblyHostBuilder builder)
    {
        builder.Logging.SetMinimumLevel(LogLevel.None);

        LoggerConfiguration loggerConfiguration = new();

        loggerConfiguration.MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning);
        loggerConfiguration.MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning);

        loggerConfiguration.WriteTo.BrowserHttp($"{builder.HostEnvironment.BaseAddress}ingest");

        Log.Logger = loggerConfiguration.CreateLogger();

        builder.Services.AddLogging(loggingBuilder => loggingBuilder.AddSerilog(dispose: true));
    }

    public static void AddPortfolioAuthentication(this IServiceCollection services)
    {
        services.AddAuthorizationCore();
        services.AddCascadingAuthenticationState();
        services.AddAuthenticationStateDeserialization();
    }

    public static void AddPortfolioServices(this IServiceCollection services)
    {
        static void APIClient(HttpClient client) => client.BaseAddress = new(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development" ? "https://localhost:7235/" : "https://localhost:7235/"); // TODO if not development, use production URL

        services.AddHttpClient<IAuthService, ClientAuthService>(APIClient);
        services.AddHttpClient<IUserService, ClientUserService>(APIClient);
    }
}