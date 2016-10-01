using Microsoft.AspNetCore.Identity;
using MongoDB.AspNetCore.Identity;
using MongoDB.Driver;
using System;
using Xunit;

namespace Tests
{
    public class UserStoreTest
    {
        public readonly string ConnectionStringWithDbName = "mongodb://localhost/test";
        public readonly string DatabaseName = "test";

        [Fact]
        public void UserStoreConstructorTests() 
        {
            MongoUserStore<IdentityUser> userStore = new MongoUserStore<IdentityUser>(ConnectionStringWithDbName);
            MongoClient mongoClient = new MongoClient(new MongoUrl(ConnectionStringWithDbName));
            IMongoDatabase db = mongoClient.GetDatabase(DatabaseName);
            userStore = new MongoUserStore<IdentityUser>(db);
            Assert.True(true);
        }

        [Fact]
        public void CreateAndDeleteUserTest()
        {
            MongoUserStore<IdentityUser> userStore = new MongoUserStore<IdentityUser>(ConnectionStringWithDbName);
            //ClaimsIdentityOptions options = new ClaimsIdentityOptions();
            //PasswordHasherOptions passHashOptions = new PasswordHasherOptions();
            //IPasswordHasher<IdentityUser> passHasher = new PasswordHasher<IdentityUser>();
            //IUserValidator<IdentityUser> userValidator = new UserValidator<IdentityUser>();
            //UserManager<IdentityUser> userManager = new UserManager<IdentityUser>(userStore, options, passHasher, userValidator, );
            IdentityUser identityUser = new IdentityUser() { UserName = "jase" };
            identityUser.Email = "jase@mail.com";
            
        }

    }
}
