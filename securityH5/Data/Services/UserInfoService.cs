using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using securityH5.Data.Models;
using YamlDotNet.Core.Tokens;
using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;
using System.Security.Policy;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using securityH5.Data.DTO;

namespace securityH5.Data.Services
{

    public class UserInfoService
    {



        #region Property
        // the number of rounds Bcrypt should run for
        private const int WorkFactor = 10;
        private readonly ApplicationDbContext _appDBContext;
        private IHttpContextAccessor _httpContextAccessor;
        #endregion

        #region Constructor
        public UserInfoService(ApplicationDbContext appDBContext, IHttpContextAccessor httpContextAccessor)
        {
            _appDBContext = appDBContext;
            _httpContextAccessor = httpContextAccessor;

        }

        #endregion

        #region Get List of infos
        public async Task<List<userRequest>> GetAllInfosAsync(string name)
        {
            var userInfoList = await _appDBContext.UserInfos.ToListAsync();
            List<userRequest> UserShow = new List<userRequest>();

            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(name));
            argon2.DegreeOfParallelism = 8; // four cores
            argon2.Iterations = 4;
            argon2.MemorySize = 1024 * 1024; // 1 GB

            foreach (var userInfo in userInfoList)
            {
                argon2.Salt = userInfo.Accountsalt;


                var computedHash = argon2.GetBytes(16);
                var isMatched = await Checkvalues(computedHash, userInfo.AccountHash);
                if (isMatched)
                {
                    var accountsalt = userInfo.Accountsalt;
                    var accountHash = userInfo.AccountHash;
                    var title = userInfo.Title;
                    var message = userInfo.Message;

                    var result = await Decryption(accountsalt,accountHash,title,message);
                    var userReq = new userRequest
                    {
                        Title = result.Item1,
                        Message = result.Item2,
                    };
                    UserShow.Add(userReq);

                }
            }


            return UserShow;
        }



        public async Task<bool> Checkvalues(byte[] computedHash, byte[]? hashfromdB)
        {

            return (computedHash.SequenceEqual(hashfromdB));

        }
        #endregion

        #region Insert UserInfo
        public async Task<bool> InsertUserInfoAsync(UserInfo userinfo, string name)
        {

            //For the Hash
            var salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            userinfo.Accountsalt = salt;

            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(name));

            argon2.Salt = salt;
            
            argon2.DegreeOfParallelism = 8; // four cores
            argon2.Iterations = 4;
            argon2.MemorySize = 1024 * 1024; // 1 GB

            userinfo.AccountHash =  argon2.GetBytes(16);

            var result = await Encryption(userinfo.Accountsalt,userinfo.AccountHash, title: userinfo.Title, message: userinfo.Message);

            userinfo.Title = result.Item1;
            userinfo.Message = result.Item2;

            await _appDBContext.UserInfos.AddAsync(userinfo);
            await _appDBContext.SaveChangesAsync();

            return true;


        }

        public async Task<(string, string)> Encryption(byte[] accountSalt, byte[]? accountHash,string? title, string? message)
        {

            byte[] titleBytes = Encoding.UTF8.GetBytes(title);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            using (var aes = Aes.Create())
            {
                aes.Key = accountHash;
                aes.IV = accountSalt;

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] ciphertitleBytes = encryptor.TransformFinalBlock(titleBytes, 0, titleBytes.Length);
                     title = Convert.ToBase64String(ciphertitleBytes);

                    byte[] ciphermessageBytes = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                    message = Convert.ToBase64String(ciphermessageBytes);


                }
            }




            return (title,message);

        }

        public async Task<(string?, string?)> Decryption(byte[] accountSalt, byte[]? accountHash, string? title, string? message)
        {
            byte[] ciphertitleBytes = Convert.FromBase64String(title);
            byte[] ciphermessageBytes = Convert.FromBase64String(message);

            using (var aes = Aes.Create())
            {
                aes.Key = accountHash;
                aes.IV = accountSalt;

                using (var decryptor = aes.CreateDecryptor())
                {
                    byte[] titleBytes = decryptor.TransformFinalBlock(ciphertitleBytes, 0, ciphertitleBytes.Length);
                    title = Encoding.UTF8.GetString(titleBytes);

                    byte[] messageBytes = decryptor.TransformFinalBlock(ciphermessageBytes, 0, ciphermessageBytes.Length);
                    message = Encoding.UTF8.GetString(messageBytes);
                }
            }

            return (title, message);
        }
        #endregion

        #region Get UserInfo by Hash
        public async Task<System.Security.Claims.ClaimsPrincipal?> GetinfoAsync()
        {
            var user = _httpContextAccessor.HttpContext?.User;

            return user;



        }


        #endregion

        #region Update UserInfo
        public async Task<bool> UpdateUserInfoAsync(UserInfo userinfo)
        {
            _appDBContext.UserInfos.Update(userinfo);
            await _appDBContext.SaveChangesAsync();
            return true;
        }
        #endregion

        #region Delete UserInfo
        public async Task<bool> DeleteUserInfoAsync(UserInfo userinfo)
        {
            _appDBContext.Remove(userinfo);
            await _appDBContext.SaveChangesAsync();
            return true;
        }
        #endregion



    }
}