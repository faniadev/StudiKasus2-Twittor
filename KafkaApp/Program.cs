using System;
using System.Collections.Generic;
using Confluent.Kafka;
using Confluent.Kafka.Admin;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
//using KafkaApp.Models;

namespace KafkaApp
{
    public class Program
    {
        //static async Task<int> Main(string[] args)
        //{
        //    var builder = new ConfigurationBuilder()
        //            .AddJsonFile($"appsettings.json", true, true);

        //    var config = builder.Build();


        //    var Serverconfig = new ConsumerConfig
        //    {
        //        BootstrapServers = config["Settings:KafkaServer"],
        //        GroupId = "tester",
        //        AutoOffsetReset = AutoOffsetReset.Earliest
        //    };
        //    CancellationTokenSource cts = new CancellationTokenSource();
        //    Console.CancelKeyPress += (_, e) => {
        //        e.Cancel = true; // prevent the process from terminating.
        //        cts.Cancel();
        //    };
        //    Console.WriteLine("--------------Twittor dot com--------------");
        //    using (var consumer = new ConsumerBuilder<string, string>(Serverconfig).Build())
        //    {
        //        Console.WriteLine("Connected");
        //        var topics = new string[] { "user", "role", "userrole", "twittor", "comment", "delete", "changepassword", "updateprofile", };
        //        consumer.Subscribe(topics);

        //        Console.WriteLine("Waiting messages....");
        //        try
        //        {
        //            while (true)
        //            {
                        //var cr = consumer.Consume(cts.Token);
                        //Console.WriteLine($"Consumed record with Topic: {cr.Topic} key: {cr.Message.Key} and value: {cr.Message.Value}");

                        //using (var dbcontext = new TwittorContext())
                        //{
                        //    if (cr.Topic == "product")
                        //    {
                        //        Product product = JsonConvert.DeserializeObject<Product>(cr.Message.Value);
                        //        dbcontext.Products.Add(product);
                        //    }
                        //    if (cr.Topic == "cart")
                        //    {
                        //        Cart cart = JsonConvert.DeserializeObject<Cart>(cr.Message.Value);
                        //        dbcontext.Carts.Add(cart);
                        //    }
                        //    await dbcontext.SaveChangesAsync();
                        //    Console.WriteLine("Data was saved into database");
                        //}


            //        }
            //    }
            //    catch (OperationCanceledException)
            //    {
            //        // Ctrl-C was pressed.
            //    }
            //    finally
            //    {
            //        consumer.Close();
            //    }

            //}

            //return 1;
        
    }
}
