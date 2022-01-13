using System;
namespace TwittorAPI.GraphQL
{
    public record CommentInput
    (
        int TwittorId,
        string Reply
    );
}
