using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using securityH5.Data.Models;

namespace securityH5.Data.Services
{

    public class UserInfoService
    {

        #region Property
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

        #region Insert UserInfo
        public async Task<bool> InsertUserInfoAsync(UserInfo userinfo)
        {

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