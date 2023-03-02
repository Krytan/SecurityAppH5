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

        #region Get List of Employees
        public async Task<List<UserInfo>> GetAllInfosAsync(string name)
        {


            foreach (var item in userInfoList)
            {
                if (BCrypt.Net.BCrypt.Verify(item.Message, name))
                {
                    // Add the decrypted item to the list
                    decryptedList.Add(BCrypt.Net.BCrypt.HashPassword(item));
                }


            }
        

            return await _appDBContext.UserInfos.ToListAsync();
        }
        #endregion

        #region Insert UserInfo
        public async Task<bool> InsertUserInfoAsync(UserInfo userinfo)
        {

                // Generate a salt and hash the item using Bcrypt
                var salt = userinfo.AccountHash;
                salt = BCrypt.Net.BCrypt.GenerateSalt(5);

                var hashedItem = BCrypt.Net.BCrypt.HashPassword(userinfo.Message, salt);
                var hashedItem2 = BCrypt.Net.BCrypt.HashPassword(userinfo.Title, salt);

            userinfo.Message = hashedItem;
            userinfo.Title = hashedItem2;


            await _appDBContext.UserInfos.AddAsync(userinfo);
            await _appDBContext.SaveChangesAsync();
            return true;
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