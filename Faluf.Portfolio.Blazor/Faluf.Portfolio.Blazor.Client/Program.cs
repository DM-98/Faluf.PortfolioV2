using System.Globalization;
using Faluf.Portfolio.Blazor.Client.Helpers;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.JSInterop;

WebAssemblyHostBuilder builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.AddPortfolioCore();

builder.Services.AddPortfolioAuthentication();
builder.Services.AddPortfolioServices();
builder.Services.AddLocalization();

WebAssemblyHost host = builder.Build();

const string defaultCulture = "en-US";

IJSRuntime js = host.Services.GetRequiredService<IJSRuntime>();
string result = await js.InvokeAsync<string>("blazorCulture.get");
CultureInfo culture = CultureInfo.GetCultureInfo(result ?? defaultCulture);

if (result is null)
{
    await js.InvokeVoidAsync("blazorCulture.set", defaultCulture);
}

CultureInfo.DefaultThreadCurrentCulture = culture;
CultureInfo.DefaultThreadCurrentUICulture = culture;

await host.RunAsync();