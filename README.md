# SimpleLdapClient

LDAP Directories are often quite useful beasts, but automating against them can be painful.

The syntax and methodology for managing info in the tree is often something a developer doesn't have, and to be fair, doesn't want.

SimpleLdapClient attempts to abstract much of that behind basic functions that do what the developer intends without requiring overmuch understanding of LDAP itself.

These libraries presume a very basic setup according to RFC 2307, which means that group membership is stored in the group object as memberUid attributes, not in the user objects as memberOf fields.

Under this design, one would search for the groups for a user via the following search:

    ldapsearch -x "(&(objectClass=posixGroup)(memberUid=<name>))" cn
    
and would expect a list of CN's that correspond to groups the user is a member of.

This library assumes a pretty standard layout, the admin username is 'admin', groups are in an OU called 'groups', users are in an OU named 'users'.

Undoubtedly this could use further abstraction, but hey, it's a 'simple' client that if nothing else can be used as a jumping off point for your own awesomeitude.

## Examples

Create a client and connect:

	lc, err := NewSimpleLdapClient("ldap://somedirectory.com", "dc=examle,dc=com", 389, false, nil)
	if err != nil {
		log.Fatalf("Failed to create client: %s", err)
	}

	err = lc.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to ldap server")
	}

Look up email for a username:

	userEmail, err := lc.EmailForUsername("bob")
	if err != nil {
		log.Fatalf("Error retrieving email for username 'bob': %s", err)
	}
	
	
Look up a user's SSH Public Key:

	userPubKey, err := lc.PubkeyForUsername("bob")

	if err != nil {
		log.Fatalf("Error retrieving pubkey for username 'bob': %s", err)
	}
	
Check to see that a user is in a group:


See if a group already exists:

	ok, err := lc.GroupExists(groupname)
	if err != nil {
		log.Printf("error searching for group %s in ldap: %s", groupname, err)
		t.Fail()
	}

	assert.True(t, ok, "Group successfully added to ldap")


Add a group:

	err = lc.AddGroup(groupname, gid)
	if err != nil {
		log.Fatalf("Failed to add group %s to ldap: %s", groupname, err)
	}

Add a user to a group:

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


Remove a user from a group:

	username := "fred"
	
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
	
Create a user (also created that user's group per posix standards):

	info := UserInfo{
		DN:        "uid=mreynolds,ou=users,dc=scribd,dc=com",
		UID:       "mreynolds",
		Shell:     "/bin/bash",
		UidNumber: 1001,
		GidNumber: 1001,
		CN:        "Malcom",
		SN:        "Reynolds",
		HomeDir:   "/home/mreynolds",
		Email:     "mreynolds@scribd.com",
		ShadowLastChange: 10000,
		PubKey:    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDN1812s1jlgPi4vchjNbg46oZ8smlxMwBY5j6V+phsnQyfk8bHhgWJ3MIUTNfx1OjJQreK7ct6kOJT2zhlb3AWVvZxFm/wbIZ8b91CMwacrjUvUU0zpQVqpbFrZoz0dJVXxb38jDsKwyQwxMW7tX4B14m9eFce+n48H/rDU4QDiyBvUzrWx+l9sZPn7UELhygwIp2O7xLxZHjigYnLzbK6bfwGBed3K7jg6FIjXPm2PzNf0pFrJqbSUgM9yJeUpXD83PiM1BkCRGAOaIRJxBS++UUDX46EbzMoBn/x6f/HDevjUTstcnJ4WVd8yeW2L+TzL/Wr5OvWp3OpWnCKvmx/10USW+PLbCvLB+iCyKzg2EMAsya31EvKAnlT0YGDvQozCer0lMuQTFdkPGB3FNRjv9WNvRFJmVH8jsOxFiNcC+UF/gOYa/CZxnn+5keZ99hSlop++f4rM3ncBG1r8C+bZ1cSZWgsNehkEV0JGQT3YsJT7ytX06l8QTVWRLv4CqlbFyirtL2mlnSq29u9eW8KEap3JVUuoLwx7yG5jcaxxrV1K4FyP1ENEm88fwgQxBxhGdvlVVPVhI/2TUgpO4GTSl98b1GAxwVOUyNpV9zU2SlfyYu6HL1oen4QpzDTIjS44NOzpSPUeSmgipPI1+gRbtGY8blTNnR8orr0SMJV6Q== mreynolds@test.com",
	}
	
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

Delete a user (also deletes the group):

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

