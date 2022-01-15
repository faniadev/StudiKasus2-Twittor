using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using HotChocolate;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using TwittorAPI.Kafka;
using TwittorAPI.Models;

namespace TwittorAPI.GraphQL
{
    public class Mutation
    {
        public async Task<TransactionStatus> AddTwittorAsync(
            TwittorInput input,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var twittor = new Twittor
            {
                UserId = input.UserId,
                Tweet = input.Tweet,
                Created = DateTime.Now
            };

            var key = "twittor-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(twittor).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "twittor", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");


            return await Task.FromResult(ret);
        }

        public async Task<TransactionStatus> AddCommentAsync(
            CommentInput input,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var comment = new Comment
            {
                TwittorId = input.TwittorId,
                Reply = input.Reply,
            };

            var key = "comment-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(comment).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "comment", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");


            return await Task.FromResult(ret);
        }

        public async Task<TransactionStatus> UpdateProfileAsync(
            UpdateProfileInput input,
            [Service] TwittorContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var profile = context.Users.Where(o => o.Id == input.Id).FirstOrDefault();
            if (profile != null)
            {
                profile.FullName = input.FullName;
                profile.Email = input.Email;
                profile.Username = input.Username;
                profile.Password = BCrypt.Net.BCrypt.HashPassword(input.Password);

                var key = "update-profile-" + DateTime.Now.ToString();
                var val = JObject.FromObject(profile).ToString(Formatting.None);
                var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "editprofile", key, val);
                await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

                var ret = new TransactionStatus(result, "");
                if (!result)
                    ret = new TransactionStatus(result, "Failed to submit data");
                return await Task.FromResult(ret);
            }
            else
            {
                return new TransactionStatus(false, "Profile doesn't exist");
            }
        }

        public async Task<TransactionStatus> ChangePasswordAsync(
            ChangePasswordInput input,
            [Service] TwittorContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var akun = context.Users.Where(o => o.Username == input.Username).FirstOrDefault();
            if (akun != null)
            {
                akun.Password = BCrypt.Net.BCrypt.HashPassword(input.Password);
                var key = "change-pass-" + DateTime.Now.ToString();
                var val = JObject.FromObject(akun).ToString(Formatting.None);
                var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "changepassword", key, val);
                await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

                var ret = new TransactionStatus(result, "");
                if (!result)
                    ret = new TransactionStatus(result, "Failed to submit data");
                return await Task.FromResult(ret);
            }
            else
            {
                return new TransactionStatus(false, "User doesn't exist");
            }
        }

        public async Task<TransactionStatus> DeleteTwittorAsync(
            int Id,
            [Service] TwittorContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var tweet = context.Twittors.Where(o => o.UserId == Id).ToList();
            if (tweet != null)
            {
                var key = "delete-tweet-" + DateTime.Now.ToString();
                var val = JObject.FromObject(tweet).ToString(Formatting.None);
                var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "delete tweet", key, val);
                await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);
                var ret = new TransactionStatus(result, "");
                if (!result)
                    ret = new TransactionStatus(result, "Failed to submit data");
                return await Task.FromResult(ret);
            }
            else
            {
                return new TransactionStatus(false, "User has not tweeted yet");
            }
        }



        public async Task<TransactionStatus> RegisterUserAsync(
            RegisterUser input,
            [Service] TwittorContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var user = context.Users.Where(o => o.Username == input.UserName).FirstOrDefault();
            if (user != null)
            {
                return new TransactionStatus(false, "username already taken");
                //return await Task.FromResult(new User());
            }
            var newUser = new User
            {
                FullName = input.FullName,
                Email = input.Email,
                Username = input.UserName,
                Password = BCrypt.Net.BCrypt.HashPassword(input.Password)
            };

            var key = "user-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(newUser).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "user", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");


            return await Task.FromResult(ret);

            // var ret = context.Users.Add(newUser);
            // await context.SaveChangesAsync();

            // return await Task.FromResult(new User { 
            //     Id=newUser.Id,
            //     Username=newUser.Username,
            //     Email =newUser.Email,
            //     FullName=newUser.FullName
            // });


            
        }

        public async Task<UserToken> LoginAsync(
            LoginUser input,
            [Service] IOptions<TokenSettings> tokenSettings,
            [Service] TwittorContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var user = context.Users.Where(o => o.Username == input.Username).FirstOrDefault();
            if (user == null)
            {
                return await Task.FromResult(new UserToken(null, null, "Username or password was invalid"));
            }
            bool valid = BCrypt.Net.BCrypt.Verify(input.Password, user.Password);
            if (valid)
            {
                var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenSettings.Value.Key));
                var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

                var claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.Name, user.Username));

                foreach (var userRole in user.UserRoles)
                {
                    var role = context.Roles.Where(o => o.Id == userRole.RoleId).FirstOrDefault();
                    if (role != null)
                    {
                        claims.Add(new Claim(ClaimTypes.Role, role.Name));
                    }
                }

                var expired = DateTime.Now.AddHours(3);
                var jwtToken = new JwtSecurityToken(
                    issuer: tokenSettings.Value.Issuer,
                    audience: tokenSettings.Value.Audience,
                    expires: expired,
                    claims: claims,
                    signingCredentials: credentials
                );

                var key = "user-login-" + DateTime.Now.ToString();
                var val = JObject.FromObject(new { Message = $"{input.Username} has signed in" }).ToString(Formatting.None);
                await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

                return await Task.FromResult(
                    new UserToken(new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expired.ToString(), null));
                //return new JwtSecurityTokenHandler().WriteToken(jwtToken);
            }

            return await Task.FromResult(new UserToken(null, null, Message: "Username or password was invalid"));
        }

         public async Task<TransactionStatus> AddRoleAsync(
            string roleName,
            [Service] TwittorContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var role = context.Roles.Where(o => o.Name == roleName).FirstOrDefault();
            if (role != null)
            {
                return new TransactionStatus(false, "Role already exist");
            }
            var newRole = new Role
            {
                Name = roleName
            };

            var key = "role-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(newRole).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "role", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");

            return await Task.FromResult(ret);
        }

        public async Task<TransactionStatus> AddRoleToUserAsync(
            UserRoleInput input,
            [Service] TwittorContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var userRole = context.UserRoles.Where(o => o.UserId == input.UserId &&
            o.RoleId == input.RoleId).FirstOrDefault();
            if (userRole != null)
            {
                return new TransactionStatus(false, "Role already exist in this user");
            }

            var newUserRole = new UserRole
            {
                UserId = input.UserId,
                RoleId = input.RoleId
            };

            var key = "user-role-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(newUserRole).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "userrole", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");

            return await Task.FromResult(ret);
        }


        
    }
}


