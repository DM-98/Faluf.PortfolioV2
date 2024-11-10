using Faluf.Portfolio.Blazor.Middlewares;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Serilog;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents().AddAuthenticationStateSerialization(options => options.SerializeAllClaims = true);
builder.Services.AddControllers();
builder.Services.AddDataProtection().PersistKeysToDbContext<PortfolioDbContext>();

builder.AddPortfolioCore();

builder.Services.AddPortfolioDatabases(builder.Configuration);
builder.Services.AddPortfolioAuthentication(builder.Configuration);

builder.Services.AddPortfolioRepositories();
builder.Services.AddPortfolioServices();

builder.Services.AddOpenApi();
builder.Services.Configure<ApiBehaviorOptions>(options => options.SuppressModelStateInvalidFilter = true);
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

WebApplication app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseMigrationsEndPoint();
    app.MapOpenApi();
    app.UseSwaggerUI(options =>
    {
        options.DefaultModelsExpandDepth(-1);
        options.SwaggerEndpoint("/openapi/v1.json", "API v1");
    });
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStatusCodePagesWithReExecute("/StatusCode/{0}");

app.UseAntiforgery();
app.UseSerilogIngestion();

string[] supportedCultures = ["en-US", "da-DK"];
app.UseRequestLocalization(new RequestLocalizationOptions().SetDefaultCulture(supportedCultures[0]).AddSupportedCultures(supportedCultures).AddSupportedUICultures(supportedCultures));

app.UseCookieAuthMiddleware();

app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode().AllowAnonymous();
app.MapControllers();

app.Run();