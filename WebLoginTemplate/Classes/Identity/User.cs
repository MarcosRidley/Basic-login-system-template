using WebLoginTemplate.Classes.Identity.Interfaces;

namespace WebLoginTemplate.Classes.Identity
{
    public class User : IUser
    {
        //create user based on IUser interface
        public int? Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; } //TODO: HASH THIS
        public string Name { get; set; }
        public string Address { get; set; }
        public string Role { get; set; } //TODO: ENUM THIS
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public int LoginAttempts { get; set; }

    }
}
