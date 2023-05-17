using Microsoft.AspNetCore.Mvc;
using WebLoginTemplate.Classes.Identity;
using WebLoginTemplate.Services;

namespace WebLoginTemplate.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class IdentityController : ControllerBase
    {
        private readonly ILogger<IdentityController> _logger;
        private readonly IdentityService _identityService;

        public IdentityController(ILogger<IdentityController> logger, IdentityService identityService)
        {
            _logger = logger;
            _identityService = identityService;
        }


        [HttpPost("CreateUser")]
        public async Task<IActionResult> CreateUser([FromBody] UserDto user)
        {
           try
            { 
                if (user.Role != "counseler" && user.Role != "sindico" && user.Role != "proprietario")
                {
                    throw new ArgumentException("Invalid role value. Role must be 'counseler', 'sindico', or 'proprietario'.");
                }

                var result = await _identityService.CreateUser(user);

                if (result == null)
                {
                    return BadRequest();
                }

                return Ok(result);
            } catch (Exception e)
            {
                return BadRequest(e.Message);
            }

        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginData)
        {
            try
            {
                var result = await _identityService.Login(loginData);
                if (result == null)
                {
                    return BadRequest();
                }
                return Ok(result);
            } catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }
    }
}