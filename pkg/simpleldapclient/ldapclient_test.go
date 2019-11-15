package ldapclient

import (
	"fmt"
	"github.com/phayes/freeport"
	"github.com/scribd/go-testslapd/pkg/testslapd"
	"github.com/stretchr/testify/assert"
	"gopkg.in/ldap.v2"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

const TestLdapAdminPassword = "letmein"
const TestLdapDn = "cn=admin,dc=scribd,dc=com"

var tmpDir string
var ldapSetup bool
var slapd *testslapd.TestSlapd

func TestMain(m *testing.M) {
	setUp()

	code := m.Run()

	tearDown()

	os.Exit(code)
}

func setUp() {
	dir, err := ioutil.TempDir("", "simpleldapclient")
	if err != nil {
		fmt.Printf("Error creating temp dir %q: %s\n", tmpDir, err)
		os.Exit(1)
	}

	tmpDir = dir

	if !ldapSetup {
		port, err := freeport.GetFreePort()
		if err != nil {
			fmt.Printf("Error getting free port: %s\n", err)
			os.Exit(1)
		}

		testLdapOrg := "scribd"
		testLdapDomain := "scribd.com"
		testLdapContainerName := "ldaptest"
		testLdapAdminPassword := "letmein"
		testLdapBase := "dc=scribd,dc=com"
		testLdapImage := "docker.artifacts.lo/ops/ldaptest"
		testLdapDn := "cn=admin,dc=scribd,dc=com"

		log.Printf("Starting test server")
		ldapOrg := fmt.Sprintf("LDAP_ORGANIZATION=%s", testLdapOrg)
		ldapDomain := fmt.Sprintf("LDAP_DOMAIN=%s", testLdapDomain)
		ldapAdminPassword := fmt.Sprintf("LDAP_ADMIN_PASSWORD=%s", testLdapAdminPassword)

		slapd = testslapd.NewTestSlapd(port, ldapOrg, testLdapBase, ldapDomain, ldapAdminPassword, testLdapContainerName, testLdapImage)
		slapd.SetVerbose(true)

		slapd.SetProvisioner(func() error {
			client, err := NewSimpleLdapClient("localhost", testLdapBase, slapd.Port, false, nil)
			if err != nil {
				log.Fatal(err)
			}

			err = client.Connect()
			if err != nil {
				log.Printf("Failed to connect to ldap:; %s", err)
				return err
			}

			err = client.Conn.Bind(testLdapDn, testLdapAdminPassword)
			if err != nil {
				log.Printf("Failed to bind to ldap: %s", err)
				return err
			}

			r := ldap.NewAddRequest("dc=scribd,dc=com")
			r.Attribute("dc", []string{"scribd"})
			r.Attribute("o", []string{"scribd"})
			r.Attribute("objectClass", []string{"organization", "dcObject"})

			log.Printf("Adding base org")

			err = client.Conn.Add(r)
			if err != nil {
				log.Printf("Failed to add org to ldap: %s", err)
				//return err
			}

			log.Printf("Adding group ou")
			r = ldap.NewAddRequest("ou=group,dc=scribd,dc=com")
			r.Attribute("ou", []string{"group"})
			r.Attribute("objectClass", []string{"top", "organizationalUnit"})

			err = client.Conn.Add(r)
			if err != nil {
				log.Printf("Failed to add group to ldap: %s", err)
				//return err
			}

			r = ldap.NewAddRequest("ou=users,dc=scribd,dc=com")
			r.Attribute("ou", []string{"users"})
			r.Attribute("objectClass", []string{"top", "organizationalUnit"})

			log.Printf("Adding users ou")

			err = client.Conn.Add(r)
			if err != nil {
				log.Printf("Failed to add users to ldap: %s", err)
				//return err
			}

			log.Printf("Adding host ou")
			r = ldap.NewAddRequest("ou=hosts,dc=scribd,dc=com")
			r.Attribute("ou", []string{"hosts"})
			r.Attribute("objectClass", []string{"top", "organizationalUnit"})

			err = client.Conn.Add(r)
			if err != nil {
				log.Printf("Failed to add group to ldap: %s", err)
				//return err
			}

			log.Printf("Adding a user")

			r = ldap.NewAddRequest("uid=fred,ou=users,dc=scribd,dc=com")
			r.Attribute("objectClass", []string{"inetOrgPerson", "person", "ldapPublicKey", "posixAccount", "top", "shadowAccount"})
			r.Attribute("uid", []string{"fred"})
			r.Attribute("loginShell", []string{"/bin/bash"})
			r.Attribute("uidNumber", []string{"5555"})
			r.Attribute("gidNumber", []string{"5555"})
			r.Attribute("cn", []string{"Fred"})
			r.Attribute("sn", []string{"Flintstone"})
			r.Attribute("homeDirectory", []string{"/home/fred"})
			r.Attribute("mail", []string{"fred@test.com"})
			r.Attribute("shadowLastChange", []string{"16323"})
			r.Attribute("shadowMax", []string{"9999"})
			r.Attribute("shadowWarning", []string{"7"})
			r.Attribute("sshPublicKey", []string{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgMEH4AiFbsWYsGdGUowj5E8bb3JR9QnaUATsGiK8q7W2yxUg1L8lrxwV/JE9Bfkdx5HZostahCGQWrchMmPbnBzJzTvMKKLMaUlc3QzaLkfe9HyC7L27AtEbYS5NYJ73Ug+4vYYFE6fl2o2mYG6aLbVKen9sv5ZDJr4cvE5yKGTbAssd4bPNaSYhw/AWYkTW2j40iyUFLyN5t9HdWqiJclY3GQSVOFzWv7U8SFnzfz6xW6M8egn4FcI2Z0vTgKfSDnF3N2O3eEFRyYEBSNWip1lnLw01qARbJanthEsCk3J5Zkg4JXX8RV/rbwMg4bv8/nDBFTPXMYnK3pHUE7a3P test@test.com"})

			err = client.Conn.Add(r)
			if err != nil {
				log.Printf("Failed to add user to ldap: %s", err)
				//return err
			}

			log.Printf("Done")

			client.Conn.Close()

			return err

		})

		err = slapd.StartTestServer()
		if err != nil {
			fmt.Printf("Failed starting slapd container %q: %s", slapd.ContainerName, err)
			log.Fatal(err)
		}

		err = slapd.Provision()
		if err != nil {
			fmt.Printf("Failed running provisioner: %s", err)
			log.Fatal(err)
		}

		ldapSetup = true
		log.Printf("Test directory set up.  Moving on.\n")
	}
}

func tearDown() {
	err := slapd.StopTestServer()
	if err != nil {
		log.Fatalf(err.Error())
	}

	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		_ = os.Remove(tmpDir)
	}
}

func TestSimpleLdapClient_EmailForUsername(t *testing.T) {
	lc, err := NewSimpleLdapClient("localhost", slapd.Base, slapd.Port, false, nil)
	if err != nil {
		fmt.Printf("Failed to create client: %s", err)
		t.Fail()
	}

	err = lc.Connect()
	if err != nil {
		log.Printf("Failed to connect to ldap server")
		t.Fail()
	}

	userEmail, err := lc.EmailForUsername(testUserName())
	if err != nil {
		fmt.Println(fmt.Sprintf("Error retrieving email for username %q: %s", testUserName(), err))
		t.Fail()
	}

	assert.Equal(t, testUserEmail(), userEmail, "Retrieved user email matches expectations.")
}

func TestSimpleLdapClient_PubkeyForUsername(t *testing.T) {
	lc, err := NewSimpleLdapClient("localhost", slapd.Base, slapd.Port, false, nil)
	if err != nil {
		fmt.Printf("Failed to create client: %s", err)
		t.Fail()
	}

	userPubKey, err := lc.PubkeyForUsername(testUserName())

	if err != nil {
		fmt.Println(fmt.Sprintf("Error retrieving pubkey for user %q: %s", testUserName(), err))
		t.Fail()
	}

	assert.Equal(t, testUserPubkey(), userPubKey, "Retrieved user public key matches expectations.")
}

func TestSimpleLdapClient_GroupOps(t *testing.T) {
	lc, err := NewSimpleLdapClient("localhost", slapd.Base, slapd.Port, false, nil)
	if err != nil {
		fmt.Printf("Failed to create client: %s", err)
		t.Fail()
	}

	err = lc.Connect()
	if err != nil {
		log.Printf("Failed to connect to ldap:; %s", err)
		t.Fail()
	}

	err = lc.Conn.Bind(TestLdapDn, TestLdapAdminPassword)
	if err != nil {
		log.Printf("Failed to bind to ldap: %s", err)
		t.Fail()
	}

	groupname := "admin"
	gid := 1000

	err = lc.AddGroup(groupname, gid)
	if err != nil {
		log.Printf("Failed to add group %s to ldap: %s", groupname, err)
		t.Fail()
	}

	ok, err := lc.GroupExists(groupname)
	if err != nil {
		log.Printf("error searching for group %s in ldap: %s", groupname, err)
		t.Fail()
	}

	assert.True(t, ok, "Group successfully added to ldap")

	username := "fred"

	err = lc.AddUserToGroup(username, groupname)
	if err != nil {
		log.Printf("error adding user %s to group %s: %s", username, groupname, err)
		t.Fail()
	}

	ok, err = lc.UserInGroup(username, groupname)
	if err != nil {
		log.Printf("error checking for user %s in group %s: %s", username, groupname, err)
		t.Fail()
	}

	assert.True(t, ok, "test user successfully added to group")

	groups, err := lc.GroupsForUsername(testUserName())

	if err != nil {
		fmt.Printf("Error retrieving groups for user %q: %s", testUserName(), err)
		t.Fail()
	}

	assert.True(t, StringInSlice(testUserGroup(), groups), "Test user is in test group")

	groupnames, err := lc.UnixGroupNames()
	if err != nil {
		fmt.Printf("Error retrieving groups in ldap: %s", err)
		t.Fail()
	}

	assert.Equal(t, []string{"admin"}, groupnames, "returned group names match expectations")

	err = lc.RemoveUserFromGroup(username, groupname)
	if err != nil {
		log.Printf("error removing user %s to group %s: %s", username, groupname, err)
		t.Fail()
	}

	ok, err = lc.UserInGroup(username, groupname)
	if err != nil {
		log.Printf("error checking for user %s in group %s: %s", username, groupname, err)
		t.Fail()
	}

	assert.False(t, ok, "test user successfully removed from group")

	err = lc.RemoveGroup(groupname)
	if err != nil {
		log.Printf("error removing group %s: %s", groupname, err)
		t.Fail()
	}

	ok, err = lc.GroupExists(groupname)
	if err != nil {
		log.Printf("error searching for group %s in ldap: %s", groupname, err)
		t.Fail()
	}

	assert.False(t, ok, "Group successfully removed from ldap")
}

func TestSimpleLdapCLient_UserOps(t *testing.T) {
	lc, err := NewSimpleLdapClient("localhost", slapd.Base, slapd.Port, false, nil)
	if err != nil {
		fmt.Printf("Failed to create client: %s", err)
		t.Fail()
	}

	err = lc.Connect()
	if err != nil {
		log.Printf("Failed to connect to ldap:; %s", err)
		t.Fail()
	}

	err = lc.Conn.Bind(TestLdapDn, TestLdapAdminPassword)
	if err != nil {
		log.Printf("Failed to bind to ldap: %s", err)
		t.Fail()
	}

	info := testUserInfo()

	// add user
	err = lc.AddUser(info)
	if err != nil {
		log.Printf("Failed to add user %s to ldap: %s", info.UID, err)
		t.Fail()
	}

	// verify user exists
	ok, err := lc.UserExists(info.UID)
	if err != nil {
		log.Printf("error searching for user %s in ldap: %s", info.UID, err)
		t.Fail()
	}

	assert.True(t, ok, "User successfully added to ldap")

	// verify group exists
	ok, err = lc.GroupExists(info.UID)
	if err != nil {
		log.Printf("error searching for group %s in ldap: %s", info.UID, err)
		t.Fail()
	}

	assert.True(t, ok, "Group successfully added to ldap")

	// verify user in group
	ok, err = lc.UserInGroup(info.UID, info.UID)
	if err != nil {
		log.Printf("error checking for user %s in group %s: %s", info.UID, info.UID, err)
		t.Fail()
	}

	usernames, err := lc.UserNames()
	if err != nil {
		fmt.Printf("Error retrieving users from ldap: %s", err)
		t.Fail()
	}

	assert.Equal(t, []string{"fred", "mreynolds"}, usernames, "returned user names match expectations")

	err = lc.ModUser(testModUserInfo())
	if err != nil {
		fmt.Printf("Error modifying user %s: %s", testModUserInfo().UID, err)
		t.Fail()
	}

	info, err = lc.GetUser(testModUserInfo().UID)
	if err != nil {
		fmt.Printf("Error retrieving user %s: %s", testModUserInfo().UID, err)
		t.Fail()
	}

	assert.Equal(t, testModUserInfo(), info, "retrieved info meets expectations")

	// remove user
	err = lc.RemoveUser(info.UID)
	if err != nil {
		log.Printf("Error removing user %s from ldap: %s", info.UID, err)
		t.Fail()
	}

	// verify user removed
	ok, err = lc.UserExists(info.UID)
	if err != nil {
		log.Printf("error searching for user %s in ldap: %s", info.UID, err)
		t.Fail()
	}

	assert.False(t, ok, "User successfully added to ldap")

	// verify group removed
	ok, err = lc.GroupExists(info.UID)
	if err != nil {
		log.Printf("error searching for group %s in ldap: %s", info.UID, err)
		t.Fail()
	}

	assert.False(t, ok, "Group successfully added to ldap")
}

func testUserName() string {
	return "fred"
}

func testUserEmail() string {
	return "fred@test.com"
}

func testUserPubkey() string {
	return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgMEH4AiFbsWYsGdGUowj5E8bb3JR9QnaUATsGiK8q7W2yxUg1L8lrxwV/JE9Bfkdx5HZostahCGQWrchMmPbnBzJzTvMKKLMaUlc3QzaLkfe9HyC7L27AtEbYS5NYJ73Ug+4vYYFE6fl2o2mYG6aLbVKen9sv5ZDJr4cvE5yKGTbAssd4bPNaSYhw/AWYkTW2j40iyUFLyN5t9HdWqiJclY3GQSVOFzWv7U8SFnzfz6xW6M8egn4FcI2Z0vTgKfSDnF3N2O3eEFRyYEBSNWip1lnLw01qARbJanthEsCk3J5Zkg4JXX8RV/rbwMg4bv8/nDBFTPXMYnK3pHUE7a3P test@test.com"
}

func testUserGroup() string {
	return "admin"
}

func testUserInfo() UserInfo {
	info := UserInfo{
		DN:               "uid=mreynolds,ou=users,dc=scribd,dc=com",
		UID:              "mreynolds",
		Shell:            "/bin/bash",
		UidNumber:        1001,
		GidNumber:        1001,
		CN:               "Malcom",
		SN:               "Reynolds",
		HomeDir:          "/home/mreynolds",
		Email:            "mreynolds@scribd.com",
		ShadowLastChange: 10000,
		PubKey:           "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDN1812s1jlgPi4vchjNbg46oZ8smlxMwBY5j6V+phsnQyfk8bHhgWJ3MIUTNfx1OjJQreK7ct6kOJT2zhlb3AWVvZxFm/wbIZ8b91CMwacrjUvUU0zpQVqpbFrZoz0dJVXxb38jDsKwyQwxMW7tX4B14m9eFce+n48H/rDU4QDiyBvUzrWx+l9sZPn7UELhygwIp2O7xLxZHjigYnLzbK6bfwGBed3K7jg6FIjXPm2PzNf0pFrJqbSUgM9yJeUpXD83PiM1BkCRGAOaIRJxBS++UUDX46EbzMoBn/x6f/HDevjUTstcnJ4WVd8yeW2L+TzL/Wr5OvWp3OpWnCKvmx/10USW+PLbCvLB+iCyKzg2EMAsya31EvKAnlT0YGDvQozCer0lMuQTFdkPGB3FNRjv9WNvRFJmVH8jsOxFiNcC+UF/gOYa/CZxnn+5keZ99hSlop++f4rM3ncBG1r8C+bZ1cSZWgsNehkEV0JGQT3YsJT7ytX06l8QTVWRLv4CqlbFyirtL2mlnSq29u9eW8KEap3JVUuoLwx7yG5jcaxxrV1K4FyP1ENEm88fwgQxBxhGdvlVVPVhI/2TUgpO4GTSl98b1GAxwVOUyNpV9zU2SlfyYu6HL1oen4QpzDTIjS44NOzpSPUeSmgipPI1+gRbtGY8blTNnR8orr0SMJV6Q== mreynolds@test.com",
	}

	return info
}

func testModUserInfo() UserInfo {
	info := UserInfo{
		DN:               "uid=mreynolds,ou=users,dc=scribd,dc=com",
		UID:              "mreynolds",
		Shell:            "/bin/bash",
		UidNumber:        1002,
		GidNumber:        1002,
		CN:               "Malcom",
		SN:               "Reynolds",
		HomeDir:          "/home/mreynolds",
		Email:            "mreynolds@scribd.com",
		ShadowLastChange: 10000,
		PubKey:           "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDN1812s1jlgPi4vchjNbg46oZ8smlxMwBY5j6V+phsnQyfk8bHhgWJ3MIUTNfx1OjJQreK7ct6kOJT2zhlb3AWVvZxFm/wbIZ8b91CMwacrjUvUU0zpQVqpbFrZoz0dJVXxb38jDsKwyQwxMW7tX4B14m9eFce+n48H/rDU4QDiyBvUzrWx+l9sZPn7UELhygwIp2O7xLxZHjigYnLzbK6bfwGBed3K7jg6FIjXPm2PzNf0pFrJqbSUgM9yJeUpXD83PiM1BkCRGAOaIRJxBS++UUDX46EbzMoBn/x6f/HDevjUTstcnJ4WVd8yeW2L+TzL/Wr5OvWp3OpWnCKvmx/10USW+PLbCvLB+iCyKzg2EMAsya31EvKAnlT0YGDvQozCer0lMuQTFdkPGB3FNRjv9WNvRFJmVH8jsOxFiNcC+UF/gOYa/CZxnn+5keZ99hSlop++f4rM3ncBG1r8C+bZ1cSZWgsNehkEV0JGQT3YsJT7ytX06l8QTVWRLv4CqlbFyirtL2mlnSq29u9eW8KEap3JVUuoLwx7yG5jcaxxrV1K4FyP1ENEm88fwgQxBxhGdvlVVPVhI/2TUgpO4GTSl98b1GAxwVOUyNpV9zU2SlfyYu6HL1oen4QpzDTIjS44NOzpSPUeSmgipPI1+gRbtGY8blTNnR8orr0SMJV6Q== mreynolds@test.com",
	}

	return info
}
