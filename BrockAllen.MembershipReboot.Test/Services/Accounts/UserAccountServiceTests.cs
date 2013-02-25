﻿using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using BrockAllen.MembershipReboot.Test.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace BrockAllen.MembershipReboot.Test.Services.Accounts
{
    [TestClass]
    public class UserAccountServiceTests
    {
        [TestClass]
        public class Ctor
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public void NullUserAccountRepo_Throws()
            {
                var sub = new UserAccountService(null, null, null);
            }
        }

        [TestClass]
        public class Dispose
        {
            [TestMethod]
            public void CallsDisposeOnUserRepo()
            {
                var userAccountRepo = new Mock<IUserAccountRepository>();
                var sub = new UserAccountService(userAccountRepo.Object, null, null);
                sub.Dispose();
                userAccountRepo.Verify(x => x.Dispose());
            }
        }

        [TestClass]
        public class SaveChanges
        {
            [TestMethod]
            public void CallsSaveChangesOnRepository()
            {
                var repo = new Mock<IUserAccountRepository>();
                var sub = new UserAccountService(repo.Object, null, null);
                sub.SaveChanges();
                repo.Verify(x => x.SaveChanges());
            }
        }

        [TestClass]
        public class GetAll
        {
            [TestInitialize]
            public void Init()
            {
                SecuritySettings.Instance = new SecuritySettings();
            }

            [TestMethod]
            public void NoParams_CallsGetAllWithNullTenant()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.GetAll();
                sub.Mock.Verify(x => x.GetAll(null));
            }

            [TestMethod]
            public void MultiTenantEnabled_NullTenant_ReturnsEmptyResults()
            {
                SecuritySettings.Instance.MultiTenant = true;
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { Tenant = "a" }, 
                    new UserAccount { Tenant = "a" }, 
                    new UserAccount { Tenant = "b" });
                var result = sub.Object.GetAll(null);
                Assert.AreEqual(0, result.Count());
            }

            [TestMethod]
            public void MultiTenantNotEnabled_NullTenant_ReturnsResultsForDefaultTenant()
            {
                SecuritySettings.Instance.MultiTenant = false;
                SecuritySettings.Instance.DefaultTenant = "a";
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { Tenant = "a" },
                    new UserAccount { Tenant = "a" },
                    new UserAccount { Tenant = "b" });
                var result = sub.Object.GetAll(null);
                Assert.AreEqual(2, result.Count());
            }

            [TestMethod]
            public void SomeAccountsClosed_ReturnsOnlyAccountsNotClosed()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID=1, Tenant = SecuritySettings.Instance.DefaultTenant, IsAccountClosed=true },
                    new UserAccount { ID=2, Tenant = SecuritySettings.Instance.DefaultTenant, IsAccountClosed=true },
                    new UserAccount { ID=3, Tenant = SecuritySettings.Instance.DefaultTenant,  },
                    new UserAccount { ID=4, Tenant = SecuritySettings.Instance.DefaultTenant,  });
                var result = sub.Object.GetAll(null);
                Assert.AreEqual(2, result.Count());
                CollectionAssert.AreEquivalent(new int[] { 3, 4 }, result.Select(x => x.ID).ToArray());
            }
        }

        [TestClass]
        public class GetByUsername
        {
            [TestInitialize]
            public void Init()
            {
                SecuritySettings.Instance = new SecuritySettings();
            }

            [TestMethod]
            public void OnlyPassUsername_PassesNullTenant()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.GetByUsername("test");
                sub.Mock.Verify(x => x.GetByUsername(null, "test"));
            }
            [TestMethod]
            public void MultiTenantEnabled_PassNullTenant_ReturnsNull()
            {
                SecuritySettings.Instance.MultiTenant = true;
                var sub = new MockUserAccountService();
                var result = sub.Object.GetByUsername(null, "test");
                Assert.IsNull(result);
            }
            [TestMethod]
            public void PassNullUsername_ReturnsNull()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.GetByUsername(null);
                Assert.IsNull(result);
            }
            [TestMethod]
            public void PassValidUsername_ReturnsCorrectResult()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "a" },
                    new UserAccount { ID = 2, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "b" },
                    new UserAccount { ID = 3, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "c" });
                var result = sub.Object.GetByUsername("b");
                Assert.AreEqual(2, result.ID);
            }
            [TestMethod]
            [ExpectedException(typeof(InvalidOperationException))]
            public void PassValidUsername_MultipleMatches_Throws()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "a" },
                    new UserAccount { ID = 2, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "a" },
                    new UserAccount { ID = 3, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "c" });
                sub.Object.GetByUsername("a");
            }
            [TestMethod]
            public void PassInvalidUsername_ReturnsNull()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "a" },
                    new UserAccount { ID = 2, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "b" },
                    new UserAccount { ID = 3, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "c" });
                var result = sub.Object.GetByUsername("d");
                Assert.IsNull(result);
            }
        }

        [TestClass]
        public class GetByEmail
        {
            [TestInitialize]
            public void Init()
            {
                SecuritySettings.Instance = new SecuritySettings();
            }

            [TestMethod]
            public void OnlyPassEmail_PassesNullTenant()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.GetByEmail("test@test.com");
                sub.Mock.Verify(x => x.GetByEmail(null, "test@test.com"));
            }
            [TestMethod]
            public void MultiTenantEnabled_PassNullTenant_ReturnsNull()
            {
                SecuritySettings.Instance.MultiTenant = true;
                var sub = new MockUserAccountService();
                var result = sub.Object.GetByEmail(null, "test@test.com");
                Assert.IsNull(result);
            }
            [TestMethod]
            public void PassNullEmail_ReturnsNull()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.GetByEmail(null);
                Assert.IsNull(result);
            }
            [TestMethod]
            public void PassValidEmail_ReturnsCorrectResult()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "a" },
                    new UserAccount { ID = 2, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "b" },
                    new UserAccount { ID = 3, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "c" });
                var result = sub.Object.GetByEmail("b");
                Assert.AreEqual(2, result.ID);
            }
            [TestMethod]
            [ExpectedException(typeof(InvalidOperationException))]
            public void PassValidEmail_MultipleMatches_Throws()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "a" },
                    new UserAccount { ID = 2, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "a" },
                    new UserAccount { ID = 3, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "c" });
                sub.Object.GetByEmail("a");
            }
            [TestMethod]
            public void PassInvalidEmail_ReturnsNull()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "a" },
                    new UserAccount { ID = 2, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "b" },
                    new UserAccount { ID = 3, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "c" });
                var result = sub.Object.GetByEmail("d");
                Assert.IsNull(result);
            }
        }

        [TestClass]
        public class GetByID
        {
            [TestMethod]
            public void CallsRepositoryGetAndReturnsAccount()
            {
                var sub = new MockUserAccountService();
                var ua = new UserAccount();
                sub.UserAccountRepository.Setup(x => x.Get(1)).Returns(ua);
                var result = sub.Object.GetByID(1);
                sub.UserAccountRepository.Verify(x => x.Get(1));
                Assert.AreSame(ua, result);
            }
        }

        [TestClass]
        public class GetByVerificationKey
        {
            [TestMethod]
            public void NullKey_ReturnsNull()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.GetByVerificationKey(null);
                Assert.IsNull(result);
            }
            [TestMethod]
            public void EmptyKey_ReturnsNull()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.GetByVerificationKey("");
                Assert.IsNull(result);
            }

            [TestMethod]
            public void ValidKey_ReturnsCorrectResult()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, VerificationKey = "a" },
                    new UserAccount { ID = 2, VerificationKey = "b" },
                    new UserAccount { ID = 3, VerificationKey = "c" });
                var result = sub.Object.GetByVerificationKey("b");
                Assert.AreEqual(2, result.ID);
            }
            [TestMethod]
            [ExpectedException(typeof(InvalidOperationException))]
            public void ValidKey_MultipleMatches_Throws()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, VerificationKey = "a" },
                    new UserAccount { ID = 2, VerificationKey = "b" },
                    new UserAccount { ID = 3, VerificationKey = "b" });
                var result = sub.Object.GetByVerificationKey("b");
            }
            [TestMethod]
            public void InvalidKey_ReturnsNull()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, VerificationKey = "a" },
                    new UserAccount { ID = 2, VerificationKey = "b" },
                    new UserAccount { ID = 3, VerificationKey = "c" });
                var result = sub.Object.GetByVerificationKey("d");
                Assert.IsNull(result);
            }
        }

        [TestClass]
        public class UsernameExists
        {
            [TestInitialize]
            public void Init()
            {
                SecuritySettings.Instance = new SecuritySettings();
            }

            [TestMethod]
            public void PassJustUsername_PassesNullForTenant()
            {
                var sub = new MockUserAccountService();
                sub.Object.UsernameExists("name");
                sub.Mock.Verify(x => x.UsernameExists(null, "name"));
            }
            [TestMethod]
            public void MultiTenantEnabled_NullTenantPassed_ReturnsFalse()
            {
                SecuritySettings.Instance.MultiTenant = true;
                var sub = new MockUserAccountService();
                var result = sub.Object.UsernameExists(null, "name");
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void NullUsernamePassed_ReturnsFalse()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.UsernameExists(null);
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void UsernamesUniqueAcrossTenants_CorrectResultsReturned()
            {
                SecuritySettings.Instance.MultiTenant = true;
                SecuritySettings.Instance.UsernamesUniqueAcrossTenants = true;
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = "t1", Username = "a" },
                    new UserAccount { ID = 2, Tenant = "t1", Username = "b" },
                    new UserAccount { ID = 3, Tenant = "t2", Username = "c" });
                Assert.IsTrue(sub.Object.UsernameExists("a"));
                Assert.IsTrue(sub.Object.UsernameExists("t1", "a"));
                Assert.IsTrue(sub.Object.UsernameExists("t2", "a"));
                Assert.IsTrue(sub.Object.UsernameExists("t3", "a"));

                Assert.IsFalse(sub.Object.UsernameExists("d"));
                Assert.IsFalse(sub.Object.UsernameExists("t1", "d"));
                Assert.IsFalse(sub.Object.UsernameExists("t2", "d"));
                Assert.IsFalse(sub.Object.UsernameExists("t3", "d"));
            }
            [TestMethod]
            public void UsernamesNotUniqueAcrossTenants_CorrectResultsReturned()
            {
                SecuritySettings.Instance.MultiTenant = true;
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = "t1", Username = "a" },
                    new UserAccount { ID = 2, Tenant = "t1", Username = "b" },
                    new UserAccount { ID = 3, Tenant = "t2", Username = "a" },
                    new UserAccount { ID = 4, Tenant = SecuritySettings.Instance.DefaultTenant, Username = "d" });
                Assert.IsTrue(sub.Object.UsernameExists("t1", "a"));
                Assert.IsTrue(sub.Object.UsernameExists("t1", "b"));
                Assert.IsTrue(sub.Object.UsernameExists("t2", "a"));
                Assert.IsTrue(sub.Object.UsernameExists(SecuritySettings.Instance.DefaultTenant, "d"));

                Assert.IsFalse(sub.Object.UsernameExists("t1", "c"));
                Assert.IsFalse(sub.Object.UsernameExists("t2", "b"));
                Assert.IsFalse(sub.Object.UsernameExists("t2", "c"));
            }
        }

        [TestClass]
        public class EmailExists
        {
            [TestInitialize]
            public void Init()
            {
                SecuritySettings.Instance = new SecuritySettings();
            }

            [TestMethod]
            public void NoTenant_PassesNullTenant()
            {
                var sub = new MockUserAccountService();
                sub.Object.EmailExists("email");
                sub.Mock.Verify(x => x.EmailExists(null, "email"));
            }
            [TestMethod]
            public void MultiTenantEnabled_NullTenantParam_ReturnsFalse()
            {
                SecuritySettings.Instance.MultiTenant = true;
                var sub = new MockUserAccountService();
                var result = sub.Object.EmailExists(null, "email");
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void NullEmailParam_ReturnsFalse()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.EmailExists(null);
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void MultiTenantEnabled_ReturnsCorrectValues()
            {
                SecuritySettings.Instance.MultiTenant = true;
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = "t1", Email = "a" },
                    new UserAccount { ID = 1, Tenant = "t1", Email = "b" },
                    new UserAccount { ID = 1, Tenant = "t2", Email = "a" });
                Assert.IsTrue(sub.Object.EmailExists("t1", "a"));
                Assert.IsTrue(sub.Object.EmailExists("t1", "b"));
                Assert.IsTrue(sub.Object.EmailExists("t2", "a"));

                Assert.IsFalse(sub.Object.EmailExists("t2", "b"));
                Assert.IsFalse(sub.Object.EmailExists("t2", "c"));
                Assert.IsFalse(sub.Object.EmailExists("t3", "a"));
                Assert.IsFalse(sub.Object.EmailExists("a"));
            }
            
            [TestMethod]
            public void MultiTenantNotEnabled_ReturnsCorrectValues()
            {
                var sub = new MockUserAccountService();
                sub.MockUserAccounts(
                    new UserAccount { ID = 1, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "a" },
                    new UserAccount { ID = 1, Tenant = SecuritySettings.Instance.DefaultTenant, Email = "b" },
                    new UserAccount { ID = 1, Tenant = "t2", Email = "a" });

                Assert.IsTrue(sub.Object.EmailExists("a"));
                Assert.IsTrue(sub.Object.EmailExists("b"));
                Assert.IsTrue(sub.Object.EmailExists(SecuritySettings.Instance.DefaultTenant, "a"));
                Assert.IsTrue(sub.Object.EmailExists("t1", "b"));
                Assert.IsTrue(sub.Object.EmailExists("t2", "a"));

                Assert.IsFalse(sub.Object.EmailExists("c"));
                Assert.IsFalse(sub.Object.EmailExists("t2", "c"));
            }
        }

        [TestClass]
        public class CreateAccount
        {
            [TestInitialize]
            public void Init()
            {
                SecuritySettings.Instance = new SecuritySettings();
            }

            [TestMethod]
            public void NoTenantPassed_PassesNullTenant()
            {
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount("user", "pass", "email@test.com");
                sub.Mock.Verify(x => x.CreateAccount(null, "user", "pass", "email@test.com"));
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void MultiTenantEnabled_NullTenant_Throws()
            {
                SecuritySettings.Instance.MultiTenant = true;
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount(null, "user", "pass", "email@test.com");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullUsername_Throws()
            {
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount("tenant", null, "pass", "email@test.com");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullPassword_Throws()
            {
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount("tenant", "user", null, "email@test.com");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void NullEmail_Throws()
            {
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount("tenant", "user", "pass", null);
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void MultiTenant_EmptyTenant_Throws()
            {
                SecuritySettings.Instance.MultiTenant = true;
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount("", "user", "pass", "email@test.com");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyUsername_Throws()
            {
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount("tenant", "", "pass", "email@test.com");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyPassword_Throws()
            {
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount("tenant", "user", "", "email@test.com");
            }
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void EmptyEmail_Throws()
            {
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount("tenant", "user", "pass", "");
            }

            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void WithPasswordPolicy_PasswordNotValid_Throws()
            {
                var sub = new MockUserAccountService();
                sub.PasswordPolicy = new Mock<IPasswordPolicy>();
                sub.PasswordPolicy.Setup(x => x.ValidatePassword(It.IsAny<string>())).Returns(false);
                sub.Object.CreateAccount("user", "pass", "email@test.com");
            }

            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void InvalidEmail_Throws()
            {
                var sub = new MockUserAccountService();
                sub.Object.CreateAccount("user", "pass", "invalid");
            }

            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void UsernameAlreadyExists_Throws()
            {
                var sub = new MockUserAccountService();
                sub.Mock.Setup(x => x.UsernameExists(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
                sub.Object.CreateAccount("user", "pass", "email@test.com");
            }

            [TestMethod]
            public void UsernameAlreadyExists_EmailIsUsername_HasEmailInTheMessage()
            {
                try
                {
                    SecuritySettings.Instance.EmailIsUsername = true;
                    var sub = new MockUserAccountService();
                    sub.Mock.Setup(x => x.UsernameExists(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
                    sub.Object.CreateAccount("user", "pass", "email@test.com");
                }
                catch (ValidationException ex)
                {
                    Assert.IsTrue(ex.Message.StartsWith("Email"));
                }
                catch
                {
                    throw;
                }
            }
            [TestMethod]
            public void UsernameAlreadyExists_EmailIsNotUsername_HasUsernameInTheMessage()
            {
                try
                {
                    var sub = new MockUserAccountService();
                    sub.Mock.Setup(x => x.UsernameExists(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
                    sub.Object.CreateAccount("user", "pass", "email@test.com");
                }
                catch (ValidationException ex)
                {
                    Assert.IsTrue(ex.Message.StartsWith("Username"));
                }
                catch
                {
                    throw;
                }
            }

            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void EmailAlreadyExists_Throws()
            {
                var sub = new MockUserAccountService();
                sub.Mock.Setup(x => x.EmailExists(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
                sub.Object.CreateAccount("user", "pass", "email@test.com");
            }

            [TestMethod]
            public void ValidAccount_AddedToRepository()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.CreateAccount("user", "pass", "email@test.com");
                sub.UserAccountRepository.Verify(x => x.Add(result));
                sub.UserAccountRepository.Verify(x => x.SaveChanges());
            }

            [TestMethod]
            public void ValidAccount_ReturnsAccount()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.CreateAccount("user", "pass", "email@test.com");
                Assert.IsNotNull(result);
                Assert.AreEqual("user", result.Username);
                Assert.AreEqual("email@test.com", result.Email);
            }

            [TestMethod]
            public void RequireAccountVerification_NotificationServiceSendAccountCreateIsCalled()
            {
                SecuritySettings.Instance.RequireAccountVerification = true;

                var sub = new MockUserAccountService();
                sub.NotificationService = new Mock<INotificationService>();
                var result = sub.Object.CreateAccount("user", "pass", "email@test.com");
                sub.NotificationService.Verify(x => x.SendAccountCreate(result));
            }
            [TestMethod]
            public void DoNotRequireAccountVerification_NotificationServiceSendAccountVerifiedIsCalled()
            {
                SecuritySettings.Instance.RequireAccountVerification = false;

                var sub = new MockUserAccountService();
                sub.NotificationService = new Mock<INotificationService>();
                var result = sub.Object.CreateAccount("user", "pass", "email@test.com");
                sub.NotificationService.Verify(x => x.SendAccountVerified(result));
            }
           
        }

        [TestClass]
        public class ValidatePassword
        {
            [TestMethod]
            public void NoPasswordPolicy_NoThrow()
            {
                var sub = new MockUserAccountService();
                sub.Object.ValidatePassword("ten", "user", "pass");
            }

            [TestMethod]
            public void PasswordPolicy_Passes_NoThrow()
            {
                var sub = new MockUserAccountService();
                sub.PasswordPolicy = new Mock<IPasswordPolicy>();
                sub.PasswordPolicy.Setup(x => x.ValidatePassword(It.IsAny<string>())).Returns(true);
                sub.Object.ValidatePassword("ten", "user", "pass");
            }
            [TestMethod]
            [ExpectedException(typeof(ValidationException))]
            public void PasswordPolicy_DoesntPass_Throws()
            {
                var sub = new MockUserAccountService();
                sub.PasswordPolicy = new Mock<IPasswordPolicy>();
                sub.PasswordPolicy.Setup(x => x.ValidatePassword(It.IsAny<string>())).Returns(false);
                sub.Object.ValidatePassword("ten", "user", "pass");
            }
        }

        [TestClass]
        public class VerifyAccount
        {
            [TestMethod]
            public void InvalidKey_ReturnsFail()
            {
                var sub = new MockUserAccountService();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns((UserAccount)null);
                Assert.IsFalse(sub.Object.VerifyAccount("key"));
            }
            [TestMethod]
            public void Success_CallsVerifyAccountOnUserAccountAndSaveOnRepository()
            {
                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns(account.Object);
                
                sub.Object.VerifyAccount("key");
                
                account.Verify(x => x.VerifyAccount("key"));
                sub.UserAccountRepository.Verify(x => x.SaveChanges());
            }

            [TestMethod]
            public void VerifyAccountReturnsTrue_ReturnsTrue()
            {
                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns(account.Object);
                account.Setup(x => x.VerifyAccount(It.IsAny<string>())).Returns(true);
                Assert.IsTrue(sub.Object.VerifyAccount("key"));
            }

            [TestMethod]
            public void VerifyAccountReturnsFalse_ReturnsFalse()
            {
                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns(account.Object);
                account.Setup(x => x.VerifyAccount(It.IsAny<string>())).Returns(false);
                Assert.IsFalse(sub.Object.VerifyAccount("key"));
            }

            [TestMethod]
            public void VerifyFails_DoesNotCallNotificationService()
            {
                var sub = new MockUserAccountService();
                sub.NotificationService = new Mock<INotificationService>();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns(account.Object);
                account.Setup(x => x.VerifyAccount(It.IsAny<string>())).Returns(false);

                sub.Object.VerifyAccount("key");

                sub.NotificationService.Verify(x => x.SendAccountVerified(It.IsAny<UserAccount>()), Times.Never());
            }

            [TestMethod]
            public void VerifySucceeds_CallsNotificationService()
            {
                var sub = new MockUserAccountService();
                sub.NotificationService = new Mock<INotificationService>();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns(account.Object);
                account.Setup(x => x.VerifyAccount(It.IsAny<string>())).Returns(true);

                sub.Object.VerifyAccount("key");

                sub.NotificationService.Verify(x => x.SendAccountVerified(account.Object));
            }
        }

        [TestClass]
        public class CancelNewAccount
        {
            [TestMethod]
            public void InvalidKey_ReturnsFalse()
            {
                var sub = new MockUserAccountService();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns((UserAccount)null);
                Assert.IsFalse(sub.Object.CancelNewAccount("key"));
            }
            [TestMethod]
            public void AccountVerified_ReturnsFalse()
            {
                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns(account.Object);
                account.Object.IsAccountVerified = true;
                
                Assert.IsFalse(sub.Object.CancelNewAccount("key"));
            }
            [TestMethod]
            public void KeysDontMatch_ReturnsFalse()
            {
                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns(account.Object);
                account.Object.VerificationKey = "key1";

                Assert.IsFalse(sub.Object.CancelNewAccount("key2"));
            }
            [TestMethod]
            public void KeysMatch_ReturnsTrue()
            {
                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns(account.Object);
                account.Object.VerificationKey = "key";

                Assert.IsTrue(sub.Object.CancelNewAccount("key"));
            }
            [TestMethod]
            public void KeysMatch_DeleteAccountCalled()
            {
                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByVerificationKey(It.IsAny<string>())).Returns(account.Object);
                account.Object.VerificationKey = "key";

                sub.Object.CancelNewAccount("key");

                sub.Mock.Verify(x => x.DeleteAccount(account.Object));
            }
        }

        [TestClass]
        public class DeleteAccount
        {
            [TestInitialize]
            public void Init()
            {
                SecuritySettings.Instance = new SecuritySettings();
            }

            [TestMethod]
            public void NoTenantParam_PassesNullTenant()
            {
                var sub = new MockUserAccountService();
                sub.Object.DeleteAccount("user");
                sub.Mock.Verify(x => x.DeleteAccount(null, "user"));
            }
            [TestMethod]
            public void MultiTenantEnabled_NullTenantParam_ReturnsFail()
            {
                SecuritySettings.Instance.MultiTenant = true;

                var sub = new MockUserAccountService();
                var result = sub.Object.DeleteAccount(null, "user");
                Assert.IsFalse(result);
            }
            [TestMethod]
            public void NullUsernameParam_ReturnsFail()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.DeleteAccount((string)null);
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void NoAccountFound_ReturnsFail()
            {
                var sub = new MockUserAccountService();
                var result = sub.Object.DeleteAccount("user");
                Assert.IsFalse(result);
            }

            [TestMethod]
            public void AccountFound_ReturnsSuccess()
            {
                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByUsername(It.IsAny<string>(), It.IsAny<string>())).Returns(account.Object);
                var result = sub.Object.DeleteAccount("user");
                Assert.IsTrue(result);
            }

            [TestMethod]
            public void AccountFound_DeleteAccountCalled()
            {
                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Mock.Setup(x => x.GetByUsername(It.IsAny<string>(), It.IsAny<string>())).Returns(account.Object);
                var result = sub.Object.DeleteAccount("user");
                sub.Mock.Verify(x => x.DeleteAccount(account.Object));
            }

            [TestMethod]
            public void AllowAccountDeletion_CallsRemoveOnRepo()
            {
                SecuritySettings.Instance.AllowAccountDeletion = true;

                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                sub.Object.DeleteAccount(account.Object);

                sub.UserAccountRepository.Verify(x => x.Remove(account.Object));
            }
            [TestMethod]
            public void AllowAccountDeletionDisabled_AccountIsNotVerified_CallsRemoveOnRepo()
            {
                SecuritySettings.Instance.AllowAccountDeletion = false;

                var sub = new MockUserAccountService();
                var account = new MockUserAccount();
                account.Object.IsAccountVerified = false;
                sub.Object.DeleteAccount(account.Object);

                sub.UserAccountRepository.Verify(x => x.Remove(account.Object));
            }
            [TestMethod]
            public void AllowAccountDeletionDisabled_AccountIsVerified_SetsDisabledFlagsOnAccount()
            {
                SecuritySettings.Instance.AllowAccountDeletion = false;

                var sub = new MockUserAccountService();
                var account = new UserAccount();
                account.IsLoginAllowed = true;
                account.IsAccountVerified = true;
                sub.Object.DeleteAccount(account);

                sub.UserAccountRepository.Verify(x => x.Remove(account), Times.Never());
                Assert.AreEqual(false, account.IsLoginAllowed);
                Assert.AreEqual(true, account.IsAccountClosed);
            }
            [TestMethod]
            public void CallsSaveChangesOnRepo()
            {
                var sub = new MockUserAccountService();
                var account = new UserAccount();
                sub.Object.DeleteAccount(account);

                sub.UserAccountRepository.Verify(x => x.SaveChanges());
            }
            [TestMethod]
            public void CallsSendAccountDelete()
            {
                var sub = new MockUserAccountService();
                sub.NotificationService = new Mock<INotificationService>();
                var account = new UserAccount();
                sub.Object.DeleteAccount(account);

                sub.NotificationService.Verify(x => x.SendAccountDelete(account));
            }
        }


    }
}
