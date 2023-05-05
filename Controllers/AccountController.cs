
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseAPIController
    {
        private readonly ITokenService _tokenService;
        private readonly DataContext _context;
        public ITokenService TokenService { get; }
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")] // POST: api/account/register
        public async Task<ActionResult<UserDto>> Register(RegisterDTO registerDTO)
        {
            if(await UserExits(registerDTO.UserName)) return BadRequest("User name already exists!");

            using var hmac = new HMACSHA512();
            var user = new AppUser{
                UserName = registerDTO.UserName,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);

            await _context.SaveChangesAsync();

            return new UserDto
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login (LoginDTO loginDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(
                x => x.UserName.ToLower() == loginDto.UserName.ToLower());

            if (user==null) return Unauthorized("Username doesnot exist");

            using var hmac = new HMACSHA512(user.PasswordSalt);        
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            if(computedHash.SequenceEqual(user.PasswordHash)) 
            return new UserDto
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
            else return Unauthorized("Password is incorrect /n "+ computedHash);
        }

        public async Task<bool> UserExits(string userName)
        {
            return await _context.Users.AnyAsync(
                x => x.UserName.ToLower() == userName.ToLower());
        }

    }
}