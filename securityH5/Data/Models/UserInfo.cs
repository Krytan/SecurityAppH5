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
        
        public string? Title { get; set; }

        public string? Message { get; set; }
        [Required]
        public byte[]? AccountHash { get; set; }
        [Required]
        public byte[]? Accountsalt { get; set; }

    }



}
