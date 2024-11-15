using FluentValidation;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.MSSqlServer;
using System.Net;
using System.Reflection;
using System.Text;

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
		services.AddScoped<TokenService>();
		services.AddScoped<AuthenticationStateProvider, JWTAuthenticationStateProvider>();

		services.AddAuthentication(options =>
		{
			options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
			options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
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

			//options.Events = new JwtBearerEvents
			//{
			//	OnMessageReceived = async context =>
			//	{
			//		try
			//		{
			//			ProtectedLocalStorage protectedLocalStorage = context.HttpContext.RequestServices.GetRequiredService<ProtectedLocalStorage>();
			//			ProtectedSessionStorage protectedSessionStorage = context.HttpContext.RequestServices.GetRequiredService<ProtectedSessionStorage>();

			//			bool isPersistent = (await protectedLocalStorage.GetAsync<string>(Globals.IsPersistent)).Value is { } isPersistentString && Convert.ToBoolean(isPersistentString);

			//			context.Token = isPersistent ? (await protectedLocalStorage.GetAsync<string>(Globals.AccessToken)).Value : (await protectedSessionStorage.GetAsync<string>(Globals.AccessToken)).Value;

			//			await Console.Out.WriteAsync($"OnMessageReceived: {context.Token}");
			//		}
			//		catch(Exception ex)
			//		{
			//			await Console.Out.WriteAsync($"OnMessageReceived exception: {ex.Message}");
			//		}
			//	}
			//};
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