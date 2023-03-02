using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace securityH5.Data.Models

{
    public class UserInfo
    {
        [Key]
        public int Id { get; set; }
        [PersonalData]
        public string? Title { get; set; }
        [PersonalData]
        public string? Message { get; set; }
        [PersonalData]
        public virtual string? AccountHash { get; set; }
    }

}
