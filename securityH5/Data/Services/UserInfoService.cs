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

        #region Get List of infos
        public async Task<List<UserInfo>> GetAllInfosAsync(string name)
        {

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(name);

            var userInfoList = await _appDBContext.UserInfos.ToListAsync();

            for (int i = 0; i < userInfoList.Count; i++)
            {
                if (BCrypt.Net.BCrypt.Verify(hashedPassword,userInfoList[i].Message))
                {
                    // Update the Message property if it matches the name
                    userInfoList[i].Message = BCrypt.Net.BCrypt.Verify(userInfoList[i].Message, hashedPassword) ? BCrypt.Net.BCrypt.HashPassword(userInfoList[i].Message, hashedPassword) : userInfoList[i].Message;

                }

                if (BCrypt.Net.BCrypt.Verify(hashedPassword,userInfoList[i].Title))
                {
                    // Update the Title property if it matches the name
                    userInfoList[i].Title = BCrypt.Net.BCrypt.HashPassword(hashedPassword);
                }
            }


            return userInfoList;
        }
        #endregion

        #region Insert UserInfo
        public async Task<bool> InsertUserInfoAsync(UserInfo userinfo)
        {

                // Generate a salt and hash the item using Bcrypt

                
            var hashedpassword = BCrypt.Net.BCrypt.HashPassword(userinfo.AccountHash);
            var hashedItem = BCrypt.Net.BCrypt.HashPassword(userinfo.Message, hashedpassword);
                var hashedItem2 = BCrypt.Net.BCrypt.HashPassword(userinfo.Title, hashedpassword);

            userinfo.Message = hashedItem;
            userinfo.Title = hashedItem2;
            userinfo.AccountHash = hashedpassword;

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