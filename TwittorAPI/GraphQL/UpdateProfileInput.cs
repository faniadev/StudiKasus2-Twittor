using System;
namespace TwittorAPI.GraphQL
{
    public record UpdateProfileInput
    (
        int? Id,
        string FullName,
        string Email,
        string Username,
        string Password
    );
}
