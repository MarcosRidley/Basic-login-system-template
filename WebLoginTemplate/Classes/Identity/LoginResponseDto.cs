namespace WebLoginTemplate.Classes.Identity
{
    public class LoginResponseDto
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public string Role { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
    }
}
