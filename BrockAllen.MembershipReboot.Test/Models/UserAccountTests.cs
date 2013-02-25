﻿using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Linq;

namespace BrockAllen.MembershipReboot.Test.Models
{
    [TestClass]
    public class UserAccountTests
    {
        [TestClass]
        public class Ctor
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullTenant_Throws()
            {
                var sub = new UserAccount(null, "user", "pass", "email");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullUsername_Throws()
            {
                var sub = new UserAccount("ten", null, "pass", "email");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullPass_Throws()
            {
                var sub = new UserAccount("ten", "user", null, "email");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullEmail_Throws()
            {
                var sub = new UserAccount("ten", "user", "pass", null);
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyTenant_Throws()
            {
                var sub = new UserAccount("", "user", "pass", "email");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyUsername_Throws()
            {
                var sub = new UserAccount("ten", "", "pass", "email");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyPass_Throws()
            {
                var sub = new UserAccount("ten", "user", "", "email");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyEmail_Throws()
            {
                var sub = new UserAccount("ten", "user", "pass", "");
            }

            [TestMethod]
            public void BasicProperties_Assigned()
            {
                var sub = new MockUserAccount("ten", "user", "pass", "email");
                var now = new DateTime(2000, 2, 3, 8, 30, 0);
                sub.Setup(x => x.UtcNow).Returns(now);
                Assert.AreEqual("ten", sub.Object.Tenant);
                Assert.AreEqual("user", sub.Object.Username);
                Assert.AreEqual("email", sub.Object.Email);
                Assert.AreEqual(now, sub.Object.Created);
                sub.Verify(x => x.SetPassword("pass"));
            }

            [TestMethod]
            public void IsAccountVerified_SetProperly()
            {
                SecuritySettings.Instance = new SecuritySettings();
                SecuritySettings.Instance.RequireAccountVerification = true;
                var sub = new UserAccount("ten", "user", "pass", "email");
                Assert.IsFalse(sub.IsAccountVerified);

                SecuritySettings.Instance = new SecuritySettings();
                SecuritySettings.Instance.RequireAccountVerification = false;
                sub = new UserAccount("ten", "user", "pass", "email");
                Assert.IsTrue(sub.IsAccountVerified);
            }

            [TestMethod]
            public void IsLoginAllowed_SetProperly()
            {
                SecuritySettings.Instance = new SecuritySettings();
                SecuritySettings.Instance.AllowLoginAfterAccountCreation = true;
                var sub = new UserAccount("ten", "user", "pass", "email");
                Assert.IsTrue(sub.IsLoginAllowed);

                SecuritySettings.Instance = new SecuritySettings();
                SecuritySettings.Instance.AllowLoginAfterAccountCreation = false;
                sub = new UserAccount("ten", "user", "pass", "email");
                Assert.IsFalse(sub.IsLoginAllowed);
            }

            [TestMethod]
            public void Verification_SetProperly()
            {
                SecuritySettings.Instance = new SecuritySettings();
                SecuritySettings.Instance.RequireAccountVerification = true;
                var sub = new UserAccount("ten", "user", "pass", "email");
                Assert.IsNotNull(sub.VerificationKey);
                Assert.IsNotNull(sub.VerificationKeySent);

                SecuritySettings.Instance = new SecuritySettings();
                SecuritySettings.Instance.RequireAccountVerification = false;
                sub = new UserAccount("ten", "user", "pass", "email");
                Assert.IsNull(sub.VerificationKey);
                Assert.IsNull(sub.VerificationKeySent);
            }



        }

        [TestClass]
        public class VerifyAccount
        {
            [TestMethod]
            public void NullKey_VerificationFails()
            {
                var subject = new UserAccount();
                var result = subject.VerifyAccount(null);
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void EmptyKey_VerificationFails()
            {
                var subject = new UserAccount();
                var result = subject.VerifyAccount(null);
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void AlreadyVerified_VerificationFails()
            {
                var subject = new UserAccount();
                subject.IsAccountVerified = true;
                var result = subject.VerifyAccount("test");
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void KeysDontMatch_VerificationFails()
            {
                var subject = new UserAccount();
                subject.IsAccountVerified = true;
                subject.VerificationKey = "test1";
                var result = subject.VerifyAccount("test2");
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void KeysMatch_VerificationSucceeds()
            {
                var subject = new UserAccount();
                subject.VerificationKey = "test1";
                var result = subject.VerifyAccount("test1");
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void SuccessfulVerification_VerificationFlagsReset()
            {
                var subject = new UserAccount();
                subject.VerificationKey = "test";
                subject.VerifyAccount("test");
                Assert.AreEqual(true, subject.IsAccountVerified);
                Assert.IsNull(subject.VerificationKey);
                Assert.IsNull(subject.VerificationKeySent);
            }
            [TestMethod]
            public void FailedVerification_VerificationFlagsNotChanged()
            {
                var sent = new DateTime(2000, 2, 3);
                var subject = new UserAccount();
                subject.VerificationKey = "test1";
                subject.VerificationKeySent = sent;
                
                subject.VerifyAccount("test2");
                
                Assert.AreEqual(false, subject.IsAccountVerified);
                Assert.AreEqual("test1", subject.VerificationKey);
                Assert.AreEqual(sent, subject.VerificationKeySent);
            }
        }

        [TestClass]
        public class ChangePassword
        {
            [TestMethod]
            public void AuthenticateFails_ReturnsFail()
            {
                var subject = new MockUserAccount();
                subject
                    .Setup(x => x.Authenticate(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<TimeSpan>()))
                    .Returns(false);
                var result = subject.Object.ChangePassword("old", "new", 0, TimeSpan.Zero);
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void AuthenticateSucceeds_ReturnsSuccess()
            {
                Mock<UserAccount> subject = new MockUserAccount();
                subject
                    .Setup(x => x.Authenticate(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<TimeSpan>()))
                    .Returns(true);
                var result = subject.Object.ChangePassword("old", "new", 0, TimeSpan.Zero);
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void SuccessfulChangePassword_SetsPassword()
            {
                Mock<UserAccount> subject = new MockUserAccount();
                subject
                    .Setup(x => x.Authenticate(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<TimeSpan>()))
                    .Returns(true);
                var result = subject.Object.ChangePassword("old", "new", 0, TimeSpan.Zero);
                subject.Verify(x => x.SetPassword("new"));
            }
        }

        [TestClass]
        public class SetPassword
        {
            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void NullPassword_Throws()
            {
                var subject = new UserAccount();
                subject.SetPassword(null);
            }
            
            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void EmptyPassword_Throws()
            {
                var subject = new UserAccount();
                subject.SetPassword("");
            }

            [TestMethod]
            public void HashedPasswordUpdated()
            {
                var subject = new MockUserAccount();
                subject.Setup(x => x.HashPassword(It.IsAny<string>())).Returns("hash");
                subject.Object.SetPassword("pwd");
                Assert.AreEqual("hash", subject.Object.HashedPassword);
            }

            [TestMethod]
            public void PasswordChangedUpdated()
            {
                var subject = new MockUserAccount();
                var now = new DateTime(2000, 2, 3);
                subject.Setup(x => x.UtcNow).Returns(now);
                subject.Object.SetPassword("pwd");
                Assert.AreEqual(now, subject.Object.PasswordChanged);
            }
        }

        [TestClass]
        public class IsVerificationKeyStale
        {
            [TestMethod]
            public void VerificationKeySentIsNull_ReturnsTrue()
            {
                var subject = new MockUserAccount();
                var now = new DateTime(2000, 2, 3);
                subject.Setup(x => x.UtcNow).Returns(now);
                var result = subject.Object.IsVerificationKeyStale;
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void VerificationKeySentPastStaleDuration_ReturnsTrue()
            {
                var subject = new MockUserAccount();
                var now = new DateTime(2000, 2, 3);
                subject.Setup(x => x.UtcNow).Returns(now);
                subject.Object.VerificationKeySent = now.Subtract(TimeSpan.FromDays(UserAccount.VerificationKeyStaleDuration).Add(TimeSpan.FromSeconds(1)));
                var result = subject.Object.IsVerificationKeyStale;
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void VerificationKeySentAtExactStaleDurationInPast_ReturnsFalse()
            {
                var subject = new MockUserAccount();
                var now = new DateTime(2000, 2, 3);
                subject.Setup(x => x.UtcNow).Returns(now);
                subject.Object.VerificationKeySent = now.Subtract(TimeSpan.FromDays(UserAccount.VerificationKeyStaleDuration));
                var result = subject.Object.IsVerificationKeyStale;
                Assert.IsFalse(result);
            }
        }

        [TestClass]
        public class ResetPassword
        {
            [TestMethod]
            public void AccountNotVerified_ReturnsFail()
            {
                var subject = new UserAccount();
                subject.IsAccountVerified = false;
                var result = subject.ResetPassword();
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void AccountVerified_ReturnsSuccess()
            {
                var subject = new UserAccount();
                subject.IsAccountVerified = true;
                var result = subject.ResetPassword();
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void AccountVerified_VerificationKeyStale_VerificationKeyReset()
            {
                var subject = new MockUserAccount();
                subject.Object.IsAccountVerified = true;
                subject.Setup(x => x.IsVerificationKeyStale).Returns(true);
                subject.Setup(x => x.GenerateSalt()).Returns("salt");
                var result = subject.Object.ResetPassword();
                Assert.AreEqual("salt", subject.Object.VerificationKey);
            }

            [TestMethod]
            public void AccountVerified_VerificationKeyNotStale_VerificationKeyNotReset()
            {
                var subject = new MockUserAccount();
                subject.Object.IsAccountVerified = true;
                subject.Object.VerificationKey = "key";
                subject.Setup(x => x.IsVerificationKeyStale).Returns(false);
                var result = subject.Object.ResetPassword();
                Assert.AreEqual("key", subject.Object.VerificationKey);
            }
            
            [TestMethod]
            public void AccountVerified_VerificationKeyStale_VerificationKeySentReset()
            {
                var subject = new MockUserAccount();
                subject.Object.IsAccountVerified = true;
                subject.Setup(x => x.IsVerificationKeyStale).Returns(true);
                var now = new DateTime(2000, 2, 3);
                subject.Setup(x => x.UtcNow).Returns(now);
                var result = subject.Object.ResetPassword();
                Assert.AreEqual(now, subject.Object.VerificationKeySent);
            }
            [TestMethod]
            public void AccountVerified_VerificationKeyNotStale_VerificationKeySentNotReset()
            {
                var subject = new MockUserAccount();
                subject.Object.IsAccountVerified = true;
                subject.Setup(x => x.IsVerificationKeyStale).Returns(false);
                var now = new DateTime(2000, 2, 3);
                subject.Object.VerificationKeySent = now;
                var result = subject.Object.ResetPassword();
                Assert.AreEqual(now, subject.Object.VerificationKeySent);
            }
        }

        [TestClass]
        public class ChangePasswordFromResetKey
        {
            [TestMethod]
            public void NullKey_ReturnsFail()
            {
                var subject = new UserAccount();
                var result = subject.ChangePasswordFromResetKey(null, "new");
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void EmptyKey_ReturnsFail()
            {
                var subject = new UserAccount();
                var result = subject.ChangePasswordFromResetKey("", "new");
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void NotVerified_ReturnsFail()
            {
                var subject = new UserAccount();
                subject.IsAccountVerified = false;
                var result = subject.ChangePasswordFromResetKey("key", "new");
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void VerificationKeyStale_ReturnsFail()
            {
                var subject = new MockUserAccount();
                subject.Object.IsAccountVerified = true;
                subject.Setup(x => x.IsVerificationKeyStale).Returns(true);
                var result = subject.Object.ChangePasswordFromResetKey("key", "new");
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void KeyDoesntMatchVerificationKey_ReturnsFail()
            {
                var subject = new MockUserAccount();
                subject.Object.IsAccountVerified = true;
                subject.Setup(x => x.IsVerificationKeyStale).Returns(false);
                subject.Object.VerificationKey = "key1";
                var result = subject.Object.ChangePasswordFromResetKey("key2", "new");
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void KeyMatchesVerificationKey_ReturnsSuccess()
            {
                var subject = new MockUserAccount();
                subject.Object.IsAccountVerified = true;
                subject.Setup(x => x.IsVerificationKeyStale).Returns(false);
                subject.Object.VerificationKey = "key";
                var result = subject.Object.ChangePasswordFromResetKey("key", "new");
                Assert.IsTrue(result);
            }
            [TestMethod]
            public void ChangeSuccess_VerificationFlagsReset()
            {
                var subject = new MockUserAccount();
                subject.Object.IsAccountVerified = true;
                subject.Object.VerificationKey = "key";
                subject.Object.VerificationKeySent = new DateTime(2000, 2, 3);
                subject.Setup(x => x.IsVerificationKeyStale).Returns(false);
                var result = subject.Object.ChangePasswordFromResetKey("key", "new");
                Assert.IsNull(subject.Object.VerificationKey);
                Assert.IsNull(subject.Object.VerificationKeySent);
            }
            [TestMethod]
            public void ChangeSuccess_SetPasswordInvoked()
            {
                var subject = new MockUserAccount();
                subject.Object.IsAccountVerified = true;
                subject.Object.VerificationKey = "key";
                subject.Setup(x => x.IsVerificationKeyStale).Returns(false);
                var result = subject.Object.ChangePasswordFromResetKey("key", "new");
                subject.Verify(x => x.SetPassword("new"));
            }
            
        }

        [TestClass]
        public class Authenticate
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void FailedLoginCountZero_Throws()
            {
                var sub = new UserAccount();
                sub.Authenticate("pass", 0, TimeSpan.FromMinutes(5));
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void FailedLoginCountBelowZero_Throws()
            {
                var sub = new UserAccount();
                sub.Authenticate("pass", -1, TimeSpan.FromMinutes(5));
            }

            [TestMethod]
            public void PasswordNull_ReturnsFail()
            {
                var sub = new UserAccount();
                var result = sub.Authenticate(null, 10, TimeSpan.FromMinutes(5));
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void PasswordEmpty_ReturnsFail()
            {
                var sub = new UserAccount();
                var result = sub.Authenticate("", 10, TimeSpan.FromMinutes(5));
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void AccountNotVerified_ReturnsFail()
            {
                var sub = new UserAccount();
                sub.IsAccountVerified = false;
                var result = sub.Authenticate("pass", 10, TimeSpan.FromMinutes(5));
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void LoginNotAllowed_ReturnsFail()
            {
                var sub = new UserAccount();
                sub.IsAccountVerified = true;
                sub.IsLoginAllowed = false;
                var result = sub.Authenticate("pass", 10, TimeSpan.FromMinutes(5));
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void TooManyRecentPasswordFailures_ReturnsFail()
            {
                var sub = new MockUserAccount();
                sub.Object.IsAccountVerified = true;
                sub.Object.IsLoginAllowed = false;
                sub.Setup(x => x.HasTooManyRecentPasswordFailures(It.IsAny<int>(), It.IsAny<TimeSpan>()))
                   .Returns(true);
                var result = sub.Object.Authenticate("pass", 10, TimeSpan.FromMinutes(5));
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void TooManyRecentPasswordFailures_IncrementsFailedLoginCount()
            {
                var sub = new MockUserAccount();
                sub.Object.FailedLoginCount = 3;
                sub.Object.IsAccountVerified = true;
                sub.Object.IsLoginAllowed = true;
                sub.Setup(x => x.HasTooManyRecentPasswordFailures(It.IsAny<int>(), It.IsAny<TimeSpan>()))
                   .Returns(true);
                var result = sub.Object.Authenticate("pass", 10, TimeSpan.FromMinutes(5));
                Assert.AreEqual(4, sub.Object.FailedLoginCount);
            }

            [TestMethod]
            public void PasswordCorrect_ReturnsSuccess()
            {
                var sub = new MockUserAccount();
                sub.Object.IsAccountVerified = true;
                sub.Object.IsLoginAllowed = true;
                sub.Setup(x => x.HasTooManyRecentPasswordFailures(It.IsAny<int>(), It.IsAny<TimeSpan>()))
                   .Returns(false);
                sub.Setup(x => x.VerifyHashedPassword("pass")).Returns(true);
                var result = sub.Object.Authenticate("pass", 10, TimeSpan.FromMinutes(5));
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void Success_ResetsPasswordFailureFlags()
            {
                var sub = new MockUserAccount();
                sub.Object.IsAccountVerified = true;
                sub.Object.IsLoginAllowed = true;
                sub.Setup(x => x.HasTooManyRecentPasswordFailures(It.IsAny<int>(), It.IsAny<TimeSpan>()))
                   .Returns(false);
                sub.Setup(x => x.VerifyHashedPassword("pass")).Returns(true);
                var now = new DateTime(2000, 2, 3);
                sub.Setup(x => x.UtcNow).Returns(now);
                sub.Object.FailedLoginCount = 10;
                var result = sub.Object.Authenticate("pass", 10, TimeSpan.FromMinutes(5));
                Assert.AreEqual(0, sub.Object.FailedLoginCount);
                Assert.AreEqual(now, sub.Object.LastLogin);
            }

            [TestMethod]
            public void PasswordIncorrect_SetsLastFailedLogin()
            {
                var sub = new MockUserAccount();
                sub.Object.IsAccountVerified = true;
                sub.Object.IsLoginAllowed = true;
                sub.Setup(x => x.HasTooManyRecentPasswordFailures(It.IsAny<int>(), It.IsAny<TimeSpan>()))
                   .Returns(false);
                sub.Setup(x => x.VerifyHashedPassword(It.IsAny<string>())).Returns(false);
                var now = new DateTime(2000, 2, 3);
                sub.Setup(x => x.UtcNow).Returns(now);

                var result = sub.Object.Authenticate("pass", 10, TimeSpan.FromMinutes(5));
                Assert.AreEqual(now, sub.Object.LastFailedLogin);
            }

            [TestMethod]
            public void PasswordIncorrect_LastFailedLoginCountIsZero_SetsLastFailedCountToOne()
            {
                var sub = new MockUserAccount();
                sub.Object.IsAccountVerified = true;
                sub.Object.IsLoginAllowed = true;
                sub.Setup(x => x.HasTooManyRecentPasswordFailures(It.IsAny<int>(), It.IsAny<TimeSpan>()))
                   .Returns(false);
                sub.Setup(x => x.VerifyHashedPassword(It.IsAny<string>())).Returns(false);
                var now = new DateTime(2000, 2, 3);
                sub.Setup(x => x.UtcNow).Returns(now);
                sub.Object.FailedLoginCount = 0;

                var result = sub.Object.Authenticate("pass", 10, TimeSpan.FromMinutes(5));
                Assert.AreEqual(1, sub.Object.FailedLoginCount);
            }
            [TestMethod]
            public void PasswordIncorrect_IncrementsLastFailedCount()
            {
                var sub = new MockUserAccount();
                sub.Object.IsAccountVerified = true;
                sub.Object.IsLoginAllowed = true;
                sub.Setup(x => x.HasTooManyRecentPasswordFailures(It.IsAny<int>(), It.IsAny<TimeSpan>()))
                   .Returns(false);
                sub.Setup(x => x.VerifyHashedPassword(It.IsAny<string>())).Returns(false);
                var now = new DateTime(2000, 2, 3);
                sub.Setup(x => x.UtcNow).Returns(now);
                sub.Object.FailedLoginCount = 3;

                var result = sub.Object.Authenticate("pass", 10, TimeSpan.FromMinutes(5));
                Assert.AreEqual(4, sub.Object.FailedLoginCount);
            }
        }

        [TestClass]
        public class HasTooManyRecentPasswordFailures
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void FailedLoginCountZero_Throws()
            {
                var sub = new UserAccount();
                sub.HasTooManyRecentPasswordFailures(0, TimeSpan.FromMinutes(5));
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void FailedLoginCountBelowZero_Throws()
            {
                var sub = new UserAccount();
                sub.HasTooManyRecentPasswordFailures(-1, TimeSpan.FromMinutes(5));
            }

            [TestMethod]
            public void FailedLoginCountLow_ReturnsFalse()
            {
                var sub = new MockUserAccount();
                sub.Object.FailedLoginCount = 2;
                var duration = TimeSpan.FromMinutes(10);
                var result = sub.Object.HasTooManyRecentPasswordFailures(5, duration);
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void FailedLoginCountHigh_LastFailedLoginIsRecent_ReturnsTrue()
            {
                var sub = new MockUserAccount();
                sub.Object.FailedLoginCount = 10;

                var date = new DateTime(2003, 2, 3, 8, 30, 0);
                sub.Setup(x => x.UtcNow).Returns(date);
                sub.Object.LastFailedLogin = date.Subtract(TimeSpan.FromMinutes(1));
                var duration = TimeSpan.FromMinutes(10);

                var result = sub.Object.HasTooManyRecentPasswordFailures(5, duration);
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void FailedLoginCountHigh_LastFailedLoginIsExactDuration_ReturnsTrue()
            {
                var sub = new MockUserAccount();
                sub.Object.FailedLoginCount = 10;

                var date = new DateTime(2003, 2, 3, 8, 30, 0);
                sub.Setup(x => x.UtcNow).Returns(date);
                var duration = TimeSpan.FromMinutes(10);
                sub.Object.LastFailedLogin = date.Subtract(duration);

                var result = sub.Object.HasTooManyRecentPasswordFailures(5, duration);
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void FailedLoginCountHigh_LastFailedLoginIsNotRecent_ReturnsFalse()
            {
                var sub = new MockUserAccount();
                sub.Object.FailedLoginCount = 10;

                var date = new DateTime(2003, 2, 3, 8, 30, 0);
                sub.Setup(x => x.UtcNow).Returns(date);
                var duration = TimeSpan.FromMinutes(10);
                sub.Object.LastFailedLogin = date.Subtract(TimeSpan.FromMinutes(11));

                var result = sub.Object.HasTooManyRecentPasswordFailures(5, duration);
                Assert.IsFalse(result);
            }
        }

        [TestClass]
        public class ChangeEmailRequest
        {
            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void NewEmailIsNull_Throws()
            {
                var sub = new UserAccount();
                var result = sub.ChangeEmailRequest(null);
            }
            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void EmptyEmailIsNull_Throws()
            {
                var sub = new UserAccount();
                var result = sub.ChangeEmailRequest("");
            }
            //[Ignore]
            //[TestMethod]
            //[ExpectedException(typeof(ValidationException))]
            //public void MalFormedEmailIsNull_Throws()
            //{
            //    var sub = new UserAccount();
            //    var result = sub.ChangeEmailRequest("test");
            //}

            [TestMethod]
            public void AccountNotVerified_ReturnsFail()
            {
                var sub = new UserAccount();
                sub.IsAccountVerified = false;
                var result = sub.ChangeEmailRequest("test@test.com");
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void AccountVerified_ReturnsSuccess()
            {
                var sub = new UserAccount();
                sub.IsAccountVerified = true;
                var result = sub.ChangeEmailRequest("test@test.com");
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void ChangeEmailSuccess_VerificationKeyStale_VerificationKeyFlagsReset()
            {
                var sub = new MockUserAccount();
                sub.Object.IsAccountVerified = true;
                sub.Setup(x => x.IsVerificationKeyStale).Returns(true);
                sub.Setup(x => x.Hash(It.IsAny<string>())).Returns("hash");
                sub.Setup(x => x.GenerateSalt()).Returns("salt");
                var now = new DateTime(2000, 2, 3);
                sub.Setup(x => x.UtcNow).Returns(now);

                var result = sub.Object.ChangeEmailRequest("test@test.com");
                Assert.AreEqual("hashsalt", sub.Object.VerificationKey);
                Assert.AreEqual(now, sub.Object.VerificationKeySent);
            }

            [TestMethod]
            public void ChangeEmailSuccess_VerificationKeyDoesntMatchEmailPrefix_VerificationKeyFlagsReset()
            {
                var sub = new MockUserAccount();
                sub.Object.IsAccountVerified = true;
                sub.Setup(x => x.IsVerificationKeyStale).Returns(false);
                sub.Setup(x => x.Hash(It.IsAny<string>())).Returns("hash");
                sub.Setup(x => x.GenerateSalt()).Returns("salt");
                var now = new DateTime(2000, 2, 3);
                sub.Setup(x => x.UtcNow).Returns(now);
                sub.Object.VerificationKey = "key";

                var result = sub.Object.ChangeEmailRequest("test@test.com");
                Assert.AreEqual("hashsalt", sub.Object.VerificationKey);
                Assert.AreEqual(now, sub.Object.VerificationKeySent);
            }

            [TestMethod]
            public void ChangeEmailSuccess_VerificationKeyMatchesEmailPrefix_VerificationKeyFlagsNotReset()
            {
                var sub = new MockUserAccount();
                sub.Object.IsAccountVerified = true;
                sub.Setup(x => x.IsVerificationKeyStale).Returns(false);
                sub.Setup(x => x.Hash(It.IsAny<string>())).Returns("key");
                sub.Object.VerificationKey = "key";
                var date = new DateTime(2000, 2, 3);
                sub.Object.VerificationKeySent = date;

                var result = sub.Object.ChangeEmailRequest("test@test.com");
                Assert.AreEqual("key", sub.Object.VerificationKey);
                Assert.AreEqual(date, sub.Object.VerificationKeySent);
            }
        }

        [TestClass]
        public class ChangeEmailFromKey
        {
            [TestMethod]
            public void NullKey_ReturnsFail()
            {
                var sub = new UserAccount();
                var result = sub.ChangeEmailFromKey(null, "new@test.com");
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void EmptyKey_ReturnsFail()
            {
                var sub = new UserAccount();
                var result = sub.ChangeEmailFromKey("", "new@test.com");
                Assert.IsFalse(result);
            }
            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void NullEmail_Throws()
            {
                var sub = new UserAccount();
                var result = sub.ChangeEmailFromKey("key", null);
            }
            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void EmptyEmail_Throws()
            {
                var sub = new UserAccount();
                var result = sub.ChangeEmailFromKey("key", "");
            }
            [TestMethod]
            public void VerificationKeyStale_ReturnsFail()
            {
                var sub = new MockUserAccount();
                sub.Setup(x => x.IsVerificationKeyStale).Returns(true);
                var result = sub.Object.ChangeEmailFromKey("key", "new@test.com");
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void KeyDoesNotMatch_ReturnsFail()
            {
                var sub = new MockUserAccount();
                sub.Setup(x => x.IsVerificationKeyStale).Returns(false);
                sub.Object.VerificationKey = "key1";
                var result = sub.Object.ChangeEmailFromKey("key2", "new@test.com");
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void KeyDoesNotHaveEmailPrefix_ReturnsFail()
            {
                var sub = new MockUserAccount();
                sub.Setup(x => x.IsVerificationKeyStale).Returns(false);
                sub.Object.VerificationKey = "key";
                sub.Setup(x => x.Hash(It.IsAny<string>())).Returns("prefix");

                var result = sub.Object.ChangeEmailFromKey("key", "new@test.com");
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void KeyHasEmailPrefix_ReturnsSuccess()
            {
                var sub = new MockUserAccount();
                sub.Setup(x => x.IsVerificationKeyStale).Returns(false);
                sub.Object.VerificationKey = "prefixkey";
                sub.Setup(x => x.Hash(It.IsAny<string>())).Returns("prefix");

                var result = sub.Object.ChangeEmailFromKey("prefixkey", "new@test.com");
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void ChangeEmailFromKeySuccess_SetsNewEmail()
            {
                var sub = new MockUserAccount();
                sub.Setup(x => x.IsVerificationKeyStale).Returns(false);
                sub.Object.VerificationKey = "prefixkey";
                sub.Setup(x => x.Hash(It.IsAny<string>())).Returns("prefix");

                var result = sub.Object.ChangeEmailFromKey("prefixkey", "new@test.com");
                Assert.AreEqual("new@test.com", sub.Object.Email);
            }

            [TestMethod]
            public void ChangeEmailFromKeySuccess_VerificationKeysReset()
            {
                var sub = new MockUserAccount();
                sub.Setup(x => x.IsVerificationKeyStale).Returns(false);
                sub.Setup(x => x.Hash(It.IsAny<string>())).Returns("prefix");
                sub.Object.VerificationKey = "prefixkey";
                sub.Object.VerificationKeySent = new DateTime(2000, 2, 3);

                var result = sub.Object.ChangeEmailFromKey("prefixkey", "new@test.com");

                Assert.IsNull(sub.Object.VerificationKey);
                Assert.IsNull(sub.Object.VerificationKeySent);
            }

        }

        [TestClass]
        public class HasClaim_1
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullType_Throws()
            {
                var sub = new UserAccount();
                sub.HasClaim(null);
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyType_Throws()
            {
                var sub = new UserAccount();
                sub.HasClaim("");
            }

            [TestMethod]
            public void ClaimTypeNotInList_ReturnsFalse()
            {
                var sub = new UserAccount();
                sub.Claims = new UserClaim[] { };
                var result = sub.HasClaim("type");
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void ClaimTypeInList_ReturnsTrue()
            {
                var sub = new UserAccount();
                sub.Claims = new UserClaim[] { new UserClaim { Type = "type" } };
                var result = sub.HasClaim("type");
                Assert.IsTrue(result);
            }


        }
        [TestClass]
        public class HasClaim_2
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullType_Throws()
            {
                var sub = new UserAccount();
                sub.HasClaim(null, "val");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyType_Throws()
            {
                var sub = new UserAccount();
                sub.HasClaim("", "val");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullValue_Throws()
            {
                var sub = new UserAccount();
                sub.HasClaim("type", null);
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyValue_Throws()
            {
                var sub = new UserAccount();
                sub.HasClaim("type", "");
            }

            [TestMethod]
            public void ClaimTypeNotInList_ReturnsFalse()
            {
                var sub = new UserAccount();
                sub.Claims = new UserClaim[] { };
                var result = sub.HasClaim("type", "value");
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void ClaimTypeInList_ReturnsTrue()
            {
                var sub = new UserAccount();
                sub.Claims = new UserClaim[] { new UserClaim { Type = "type", Value="value" } };
                var result = sub.HasClaim("type", "value");
                Assert.IsTrue(result);
            }


        }

        [TestClass]
        public class GetClaimValues
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullType_Throws()
            {
                var sub = new UserAccount();
                sub.GetClaimValues(null);
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyType_Throws()
            {
                var sub = new UserAccount();
                sub.GetClaimValues("");
            }
            [TestMethod]
            public void TypeNotInList_ReturnsEmptyCollection()
            {
                var sub = new UserAccount();
                sub.Claims = new UserClaim[]{
                    new UserClaim{Type="type1", Value="a"},
                    new UserClaim{Type="type1", Value="b"},
                    new UserClaim{Type="type2", Value="c"},
                };
                var result = sub.GetClaimValues("type");
                Assert.AreEqual(0, result.Count());
            }
            [TestMethod]
            public void TypeInList_ReturnsCurrentValues()
            {
                var sub = new UserAccount();
                sub.Claims = new UserClaim[]{
                    new UserClaim{Type="type1", Value="a"},
                    new UserClaim{Type="type1", Value="b"},
                    new UserClaim{Type="type2", Value="c"},
                };
                var result = sub.GetClaimValues("type1");
                Assert.AreEqual(2, result.Count());
                CollectionAssert.AreEquivalent(new string[] { "a", "b" }, result.ToArray());
            }
        }

        [TestClass]
        public class GetClaimValue
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullType_Throws()
            {
                var sub = new UserAccount();
                sub.GetClaimValue(null);
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyType_Throws()
            {
                var sub = new UserAccount();
                sub.GetClaimValue("");
            }
            [TestMethod]
            public void TypeNotInList_ReturnsNull()
            {
                var sub = new UserAccount();
                sub.Claims = new UserClaim[]{
                    new UserClaim{Type="type1", Value="a"},
                    new UserClaim{Type="type1", Value="b"},
                    new UserClaim{Type="type2", Value="c"},
                };
                var result = sub.GetClaimValue("type");
                Assert.IsNull(result);
            }
            [TestMethod]
            public void TypeInList_ReturnsValue()
            {
                var sub = new UserAccount();
                sub.Claims = new UserClaim[]{
                    new UserClaim{Type="type1", Value="a"},
                    new UserClaim{Type="type1", Value="b"},
                    new UserClaim{Type="type2", Value="c"},
                };
                var result = sub.GetClaimValue("type2");
                Assert.AreEqual("c", result);
            }
            [TestMethod]
            [ExpectedException(typeof(InvalidOperationException))]
            public void MultipleTypeInList_Throws()
            {
                var sub = new UserAccount();
                sub.Claims = new UserClaim[]{
                    new UserClaim{Type="type1", Value="a"},
                    new UserClaim{Type="type1", Value="b"},
                    new UserClaim{Type="type2", Value="c"},
                };
                var result = sub.GetClaimValue("type1");
            }
        }

        [TestClass]
        public class AddClaim
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullType_Throws()
            {
                var sub = new UserAccount();
                sub.AddClaim(null, "value");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyType_Throws()
            {
                var sub = new UserAccount();
                sub.AddClaim("", "value");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullValue_Throws()
            {
                var sub = new UserAccount();
                sub.AddClaim("type", null);
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyValue_Throws()
            {
                var sub = new UserAccount();
                sub.AddClaim("type", "");
            }

            [TestMethod]
            public void AlreadyHasClaim_ShouldNotAddClaim()
            {
                var sub = new MockUserAccount();
                sub.Object.Claims = new List<UserClaim>();
                sub.Setup(x => x.HasClaim(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

                sub.Object.AddClaim("type", "value");

                Assert.AreEqual(0, sub.Object.Claims.Count);
            }
            [TestMethod]
            public void DoesNotHaveClaim_ShouldAddClaim()
            {
                var sub = new MockUserAccount();
                sub.Object.Claims = new List<UserClaim>();
                sub.Setup(x => x.HasClaim(It.IsAny<string>(), It.IsAny<string>())).Returns(false);

                sub.Object.AddClaim("type", "value");

                Assert.AreEqual(1, sub.Object.Claims.Count);
                Assert.AreEqual("type", sub.Object.Claims.First().Type);
                Assert.AreEqual("value", sub.Object.Claims.First().Value);
            }
        }

        [TestClass]
        public class RemoveClaim_1
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullType_Throws()
            {
                var sub = new UserAccount();
                sub.RemoveClaim(null);
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyType_Throws()
            {
                var sub = new UserAccount();
                sub.RemoveClaim("");
            }
            [TestMethod]
            public void ClaimNotFound_RemovesNoClaims()
            {
                var sub = new UserAccount();
                sub.Claims = new List<UserClaim>()
                {
                    new UserClaim{Type="type1", Value = "value"}
                };
                sub.RemoveClaim("type2");

                Assert.AreEqual(1, sub.Claims.Count);
            }
            [TestMethod]
            public void ClaimFound_RemovesClaims()
            {
                var sub = new UserAccount();
                sub.Claims = new List<UserClaim>()
                {
                    new UserClaim{Type="type1", Value = "value"},
                    new UserClaim{Type="type2", Value = "value"},
                };
                sub.RemoveClaim("type1");

                Assert.AreEqual(1, sub.Claims.Count);
                Assert.AreEqual("type2", sub.Claims.First().Type);
                Assert.AreEqual("value", sub.Claims.First().Value);
            }
            [TestMethod]
            public void MutipleClaimsFound_RemovesClaims()
            {
                var sub = new UserAccount();
                sub.Claims = new List<UserClaim>()
                {
                    new UserClaim{Type="type1", Value = "value1"},
                    new UserClaim{Type="type1", Value = "value2"},
                    new UserClaim{Type="type2", Value = "value"},
                };
                sub.RemoveClaim("type1");

                Assert.AreEqual(1, sub.Claims.Count);
                Assert.AreEqual("type2", sub.Claims.First().Type);
                Assert.AreEqual("value", sub.Claims.First().Value);
            }
        }
        [TestClass]
        public class RemoveClaim_2
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullType_Throws()
            {
                var sub = new UserAccount();
                sub.RemoveClaim(null, "value");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyType_Throws()
            {
                var sub = new UserAccount();
                sub.RemoveClaim("", "value");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullValue_Throws()
            {
                var sub = new UserAccount();
                sub.RemoveClaim("type", null);
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyValue_Throws()
            {
                var sub = new UserAccount();
                sub.RemoveClaim("type", "");
            }

            [TestMethod]
            public void ClaimNotFound_RemovesNoClaims()
            {
                var sub = new UserAccount();
                sub.Claims = new List<UserClaim>()
                {
                    new UserClaim{Type="type1", Value = "value1"}
                };
                sub.RemoveClaim("type1", "value2");
                sub.RemoveClaim("type2", "value1");

                Assert.AreEqual(1, sub.Claims.Count);
            }

            [TestMethod]
            public void ClaimFound_RemovesClaims()
            {
                var sub = new UserAccount();
                sub.Claims = new List<UserClaim>()
                {
                    new UserClaim{Type="type1", Value = "value1"},
                    new UserClaim{Type="type2", Value = "value2"},
                };
                sub.RemoveClaim("type1", "value1");

                Assert.AreEqual(1, sub.Claims.Count);
                Assert.AreEqual("type2", sub.Claims.First().Type);
                Assert.AreEqual("value2", sub.Claims.First().Value);
            }
            [TestMethod]
            public void MutipleClaimsFound_RemovesClaims()
            {
                var sub = new UserAccount();
                sub.Claims = new List<UserClaim>()
                {
                    new UserClaim{Type="type1", Value = "value1"},
                    new UserClaim{Type="type1", Value = "value1"},
                    new UserClaim{Type="type2", Value = "value2"},
                };
                sub.RemoveClaim("type1", "value1");

                Assert.AreEqual(1, sub.Claims.Count);
                Assert.AreEqual("type2", sub.Claims.First().Type);
                Assert.AreEqual("value2", sub.Claims.First().Value);
            }
        }
    }
}
