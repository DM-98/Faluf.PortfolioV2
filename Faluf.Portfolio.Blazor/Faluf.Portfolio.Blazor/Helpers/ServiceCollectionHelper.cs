using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Text;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
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

			options.Events = new JwtBearerEvents
			{
				OnMessageReceived = async context =>
				{
					ILogger<Program> logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();

					string? accessToken = context.Request.Cookies[Globals.AccessToken];

					if (string.IsNullOrWhiteSpace(accessToken))
					{
						return;
					}

					IDataProtector dataProtector = context.HttpContext.RequestServices.GetRequiredService<IDataProtectionProvider>().CreateProtector(Globals.AuthProtector);
					accessToken = dataProtector.Unprotect(accessToken);
					JwtSecurityToken jwtSecurityToken = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);

					if (jwtSecurityToken.ValidTo > DateTime.UtcNow)
					{
						context.Token = accessToken;

						return;
					}

					string refreshToken = jwtSecurityToken.Claims.First(x => x.Type is JwtRegisteredClaimNames.Jti).Value;
					IAuthService authService = context.HttpContext.RequestServices.GetRequiredService<IAuthService>();
					Result<TokenDTO> refreshTokensResult = await authService.RefreshTokensAsync(new RefreshTokenInputModel { RefreshToken = refreshToken });

					if (!refreshTokensResult.IsSuccess)
					{
						context.Response.Cookies.Delete(Globals.AccessToken);
						context.Response.Cookies.Delete(Globals.IsPersistent);

						return;
					}

					bool isPersistent = context.Request.Cookies[Globals.IsPersistent] is { } isPersistentString && Convert.ToBoolean(dataProtector.Unprotect(isPersistentString));

					CookieOptions cookieOptions = new()
					{
						IsEssential = true,
						HttpOnly = true,
						Secure = true,
						SameSite = SameSiteMode.Strict,
						Expires = isPersistent ? DateTime.UtcNow.AddYears(1) : null
					};

					context.Response.Cookies.Append(Globals.AccessToken, dataProtector.Protect(refreshTokensResult.Content.AccessToken), cookieOptions);
					context.Response.Cookies.Append(Globals.IsPersistent, dataProtector.Protect(isPersistent.ToString()), cookieOptions);

					context.Token = refreshTokensResult.Content.AccessToken;
				}
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