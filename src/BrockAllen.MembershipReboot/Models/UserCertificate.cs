﻿/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.MembershipReboot
{
    public class UserCertificate
    {
        internal protected UserCertificate()
        {
        }

        [Key]
        [Column(Order = 1)]
        public virtual Guid UserAccountID { get; set; }
        
        [Key]
        [Column(Order = 2)]
        [StringLength(150)]
        public virtual string Thumbprint { get; set; }
        
        [StringLength(250)]
        public virtual string Subject { get; set; }

        [Required]
        [ForeignKey("UserAccountID")]
        public virtual UserAccount User { get; set; }

    }
}
