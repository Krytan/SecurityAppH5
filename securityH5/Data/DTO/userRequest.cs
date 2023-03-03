using System;
using System.ComponentModel.DataAnnotations;

namespace securityH5.Data.DTO
{
    public class userRequest
    {
        public int Id { get; set; }
        public string? Title { get; set; }
        public string? Message { get; set; }
        public byte[]? AccountHash { get; set; }
        public byte[]? Accountsalt { get; set; }

    }
}

