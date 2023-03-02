using System;
using Microsoft.AspNetCore.Identity;

namespace securityH5.Data.Services
{
        public class ApplicationUser : IdentityUser
        {
            public virtual string Email { get; set; }

        }
}

