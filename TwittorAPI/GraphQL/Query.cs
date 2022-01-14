using System;
using System.Linq;
using System.Threading.Tasks;
using HotChocolate;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using TwittorAPI.Kafka;
using TwittorAPI.Models;

namespace TwittorAPI.GraphQL
{
    public class Query
    {
        public async Task<IQueryable<Twittor>> GetTwittors(
            [Service] TwittorContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var key = "GetTwittors-" + DateTime.Now.ToString();
            var val = JObject.FromObject(new { Message = "GraphQL Query GetTwittors" }).ToString(Formatting.None);

            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);
            return context.Twittors;
        }

        //public IQueryable<UserData> GetUsers([Service] ProductQLContext context) =>
        //    context.Users.Select(p => new UserData()
        //    {
        //        Id = p.Id,
        //        FullName = p.FullName,
        //        Email = p.Email,
        //        Username = p.Username
        //    });
    }
}
