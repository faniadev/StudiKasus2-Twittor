using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TwittorAPI.GraphQL
{
    public record UserRoleInput
    (
        int UserId,
        int RoleId
    );
}