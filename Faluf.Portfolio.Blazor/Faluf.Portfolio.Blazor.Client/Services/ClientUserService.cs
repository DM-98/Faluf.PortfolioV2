using System.Net.Http.Json;
using Microsoft.Extensions.Localization;

namespace Faluf.Portfolio.Blazor.Client.Services;

public sealed class ClientUserService(HttpClient httpClient, IStringLocalizer<ClientUserService> stringLocalizer) : IUserService
{
    public async Task<Result<User>> RegisterAsync(RegisterInputModel registerInputModel, CancellationToken cancellationToken = default)
    {
        try
        {
            HttpResponseMessage response = await httpClient.PostAsJsonAsync("api/User/Register", registerInputModel, cancellationToken);

            string responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

            Result<User> registerResult = await response.Content.ReadFromJsonAsync<Result<User>>(cancellationToken) ?? Result.BadRequest<User>(stringLocalizer["UnableToDeserialize"]);

            return registerResult;
        }
        catch (Exception ex)
        {
            return Result.InternalServerError<User>(stringLocalizer["InternalServerError"], ex);
        }
    }
}