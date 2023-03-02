using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using securityH5.Data.Services;

namespace securityH5.Data.Models
{

    public class Userdata : Microsoft.AspNetCore.Mvc.Controller
    {
        private UserManager<ApplicationUser> _userManager;

        public Userdata(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<string?> userhash()
        {
            var user = await _userManager.GetUserAsync(User);
            var hash = user.PasswordHash;


            return hash;
        }




    }
}

