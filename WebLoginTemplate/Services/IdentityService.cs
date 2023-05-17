using Microsoft.Data.SqlClient;
using WebLoginTemplate.Classes.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using WebLoginTemplate.Classes.Identity.Interfaces;

namespace WebLoginTemplate.Services
{
    public class IdentityService
    {
        private readonly SqlConnection _connection;

        public IdentityService(SqlConnection connection)
        {
            _connection = connection;
        }

        public async Task<User> CreateUser(UserDto user)
        {
            try
            {

            //Create a new User object from the UserDto object
            var newUser = new User
            {
                Username = user.Username,
                Password = user.Password,
                Name = user.Name,
                Address = user.Address,
                Role = user.Role,
                LoginAttempts = 0
            };
            // Generate a new JWT token for the user
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("MarcosRidleyWasHereBabey"); // Replace with your own secret key
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
                }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            newUser.Token = tokenHandler.WriteToken(token);

            // Generate a new refresh token for the user
            var refreshToken = Guid.NewGuid().ToString();
            newUser.RefreshToken = refreshToken;


            //Use the _connection to create a new SqlCommand object
            var command = _connection.CreateCommand();
            //Set the command text to the SQL query to create a user
            command.CommandText = @"INSERT INTO [dbo].[Identities] ([Username], [Password], [Name], [Address], [Role], [Token], [RefreshToken], [LoginAttempts]) VALUES (@username, @password, @name, @address, @role, @token, @refreshToken, @loginAttempts)";
            //Add the parameters to the command
            command.Parameters.AddWithValue("@username", user.Username);
            command.Parameters.AddWithValue("@password", HashPassword(user.Password));
            command.Parameters.AddWithValue("@name", user.Name);
            command.Parameters.AddWithValue("@address", user.Address);
            command.Parameters.AddWithValue("@role", user.Role);
            command.Parameters.AddWithValue("@token", newUser.Token);
            command.Parameters.AddWithValue("@refreshToken", newUser.RefreshToken);
            command.Parameters.AddWithValue("@loginAttempts", newUser.LoginAttempts);
            //Open the connection
            await _connection.OpenAsync();
            //Execute the command
            await command.ExecuteNonQueryAsync();
            //Close the connection
            _connection.Close();
            //Return the user object
            return newUser;
            } catch (SqlException ex)
            {
                if (ex.Number == 2601 || ex.Number == 2627) // Unique constraint violation error codes
                {
                    throw new ApplicationException("The username is already taken.");
                }
                else
                {
                    throw;
                }
            }
        }


        public async Task<LoginResponseDto> Login(LoginRequestDto loginRequestDto)
        {
            try
            {
                using var connection = _connection;
                await connection.OpenAsync();

                // Use a parameterized query to prevent SQL injection attacks
                var command = new SqlCommand(@"SELECT * FROM [dbo].[Identities] WHERE [Username] = @username", connection);
                command.Parameters.AddWithValue("@username", loginRequestDto.Username);

                using var reader = await command.ExecuteReaderAsync();

                if (await reader.ReadAsync())
                {
                    var passwordHash = reader.GetString(2);

                    if (VerifyPassword(loginRequestDto.Password, passwordHash))
                    {
                        // Create a new User object from the reader
                        var user = new User
                        {
                            Id = reader.GetInt32(0),
                            Username = reader.GetString(1),
                            Password = passwordHash,
                            Name = reader.GetString(3),
                            Address = reader.GetString(4),
                            Role = reader.GetString(5),
                            Token = reader.GetString(6),
                            RefreshToken = reader.GetString(7),
                            LoginAttempts = reader.GetInt32(8)
                        };

                        // Generate a new JWT token for the user
                        var tokenHandler = new JwtSecurityTokenHandler();
                        var key = Encoding.ASCII.GetBytes("MarcosRidleyWasHereBabey");
                        var tokenDescriptor = new SecurityTokenDescriptor
                        {
                            Subject = new ClaimsIdentity(new Claim[]
                            {
                        new Claim(ClaimTypes.Name, user.Username),
                        new Claim(ClaimTypes.Role, user.Role)
                            }),
                            Expires = DateTime.UtcNow.AddMinutes(30),
                            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                        };
                        var token = tokenHandler.CreateToken(tokenDescriptor);
                        user.Token = tokenHandler.WriteToken(token);

                        // Generate a new refresh token for the user
                        var refreshToken = Guid.NewGuid().ToString();
                        user.RefreshToken = refreshToken;

                        // Use a parameterized query to update the user's token and refresh token
                        command.CommandText = @"UPDATE [dbo].[Identities] SET [Token] = @token, [RefreshToken] = @refreshToken WHERE [Id] = @id";
                        command.Parameters.Clear();
                        command.Parameters.AddWithValue("@token", user.Token);
                        command.Parameters.AddWithValue("@refreshToken", user.RefreshToken);
                        command.Parameters.AddWithValue("@id", user.Id);
                        await reader.CloseAsync(); // Close the data reader before executing the second command
                        await command.ExecuteNonQueryAsync();

                        return new LoginResponseDto
                        {
                            Token = user.Token,
                            RefreshToken = user.RefreshToken,
                            Role = user.Role,
                            Name = user.Name,
                            Address = user.Address
                        };
                    }
                    else
                    {
                        throw new ApplicationException("Senha incorreta.");
                    }
                }

                throw new ApplicationException("Esse usuário não existe.");
            } 
            catch(ApplicationException ex)
            {
                throw new ApplicationException (ex.Message);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("An error occurred while logging in.", ex);
            }
        }


        private string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hashedBytes);
            }
        }

        private bool VerifyPassword(string password, string hashedPassword)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                var hashedPasswordToCompare = Convert.ToBase64String(hashedBytes);
                return hashedPassword == hashedPasswordToCompare;
            }
        }
    }
}
