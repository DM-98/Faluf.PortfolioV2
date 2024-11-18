using System.Reflection;
using System.Text;
using FluentValidation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.MSSqlServer;

namespace Faluf.Portfolio.Blazor.Helpers;

public static class ServiceCollectionHelper
{
	public static void AddPortfolioCore(this WebApplicationBuilder builder)
	{
		// Logger
		builder.Host.UseSerilog((hostingContext, loggerConfiguration) =>
		{
			loggerConfiguration.MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning);
			loggerConfiguration.MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning);

			loggerConfiguration.WriteTo.Console(LogEventLevel.Information);
			loggerConfiguration.WriteTo.MSSqlServer(
				connectionString: builder.Configuration.GetConnectionString("PortfolioConnection"),
				sinkOptions: new MSSqlServerSinkOptions { TableName = "Logs", AutoCreateSqlTable = true },
				restrictedToMinimumLevel: LogEventLevel.Warning);
		});

		// IHttpClientFactory
		builder.Services.AddHttpClient("API", client => client.BaseAddress = new Uri(builder.Configuration["API:BaseUrl"]!));

		// Localization
		builder.Services.AddLocalization();

		// Validations
		builder.Services.AddValidatorsFromAssembly(Assembly.Load("Faluf.Portfolio.Core"));
	}

	public static void AddPortfolioDatabases(this IServiceCollection services, IConfiguration configuration)
	{
		services.AddDbContextFactory<PortfolioDbContext>(options =>
		{
			options.UseSqlServer(configuration.GetConnectionString("PortfolioConnection"), options => options.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery));
			options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
		});
	}

	public static void AddPortfolioAuthentication(this IServiceCollection services, IConfiguration configuration)
	{
		services.AddCascadingAuthenticationState();
		services.AddScoped<IAuthStateRepository, AuthStateRepository>();
		services.AddScoped<IAuthService, AuthService>();
		services.AddScoped<AuthenticationStateProvider, JWTRevalidatingAuthenticationStateProvider>();
		services.AddAuthentication(options =>
		{
			options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
			options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
		}).AddCookie(options =>
		{
			options.Cookie.Name = Globals.AccessToken;
			options.Cookie.SameSite = SameSiteMode.Strict;
			options.Cookie.HttpOnly = true;
			options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
			options.Cookie.IsEssential = true;
			options.Events = new CookieAuthenticationEvents
			{
				OnValidatePrincipal = async context =>
				{
					if (context.Principal is null or { Identity.IsAuthenticated: false })
					{
						context.RejectPrincipal();

						await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

						return;
					}

					using IServiceScope scope = context.HttpContext.RequestServices.CreateScope();

					IAuthService authService = scope.ServiceProvider.GetRequiredService<IAuthService>();
					ILogger<JWTRevalidatingAuthenticationStateProvider> logger = scope.ServiceProvider.GetRequiredService<ILogger<JWTRevalidatingAuthenticationStateProvider>>();

					if (!await JWTRevalidatingAuthenticationStateProvider.ValidateAuthStateAsync(authService, context.Principal, logger, context.HttpContext.RequestAborted))
					{
						context.RejectPrincipal();

						await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
					}
				}
			};
			options.SlidingExpiration = true;
			options.LoginPath = "/login";
			options.LogoutPath = "/logout";
			options.AccessDeniedPath = "/access-denied";
		}).AddJwtBearer(options =>
		{
			options.TokenValidationParameters = new TokenValidationParameters
			{
				ValidIssuer = configuration["JWT:Issuer"]!,
				ValidAudience = configuration["JWT:Audience"]!,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]!)),
				ClockSkew = TimeSpan.Zero
			};
		});
	}

	public static void AddPortfolioRepositories(this IServiceCollection services)
	{
		services.AddScoped<IUserRepository, UserRepository>();
	}

	public static void AddPortfolioServices(this IServiceCollection services)
	{
		services.AddScoped<IUserService, UserService>();
	}
}