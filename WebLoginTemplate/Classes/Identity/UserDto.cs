using System.ComponentModel.DataAnnotations;

namespace WebLoginTemplate.Classes.Identity
{
    public class UserDto
    {
        //create user based on IUser interface
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; } //TODO: HASH THIS
        [Required]
        public string Name { get; set; }
        [Required]
        public string Address { get; set; }
        [Required]
        [RegularExpression("counselor|sindico|proprietario")]
        public string Role { get; set; } //TODO: ENUM THIS
    }
}
