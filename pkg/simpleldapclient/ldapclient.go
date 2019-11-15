package ldapclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
	"strconv"
)

const USER_FILTER = "(uid=%s)"
const GROUP_FILTER = "(&(cn=%s)(objectClass=posixGroup))"

// UserInfo is a struct for returning the basic info stored in LDAP for a posix User
type UserInfo struct {
	DN               string
	UID              string
	Shell            string
	UidNumber        int
	GidNumber        int
	ShadowLastChange int
	CN               string
	SN               string
	HomeDir          string
	Email            string
	PubKey           string
}

type SimpleLdapClient struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	Host               string
	ServerName         string
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	ClientCertificates []tls.Certificate // Adding client certificates
	CACertificate      []byte
}

// NewSimpleLdapClient creates a properly configured SimpleLdapClient or errors if not properly configured
func NewSimpleLdapClient(host string, base string, port int, ssl bool, cacert []byte) (lc *SimpleLdapClient, err error) {

	if host == "" {
		err = errors.New("Missing host in constructor")
		return lc, err
	}

	if base == "" {
		err = errors.New("Missing base in constructor")
		return lc, err
	}

	if port == 0 {
		err = errors.New("Missing port in constructor")
		return lc, err
	}

	lc = &SimpleLdapClient{
		Base:          base,
		UseSSL:        ssl,
		ServerName:    host,
		Host:          host,
		Port:          port,
		CACertificate: cacert,
	}

	return lc, err
}

// UserFilter returns a standard user filter for an ldap directory
func (lc *SimpleLdapClient) UserFilter(username string) string {
	return fmt.Sprintf("uid=%s,ou=users,%s", username, lc.Base)
}

// AdminDn returns a standard admin dn for an ldap directory
func (lc *SimpleLdapClient) AdminDn() string {
	return fmt.Sprintf("cn=admin,%s", lc.Base)
}

// Connect connects to the ldap backend.
func (lc *SimpleLdapClient) Connect() (err error) {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				err = errors.Wrapf(err, "failed to connect in the clear")
				return err
			}

		} else {
			rootCAs, err := x509.SystemCertPool()
			if err != nil {
				err = errors.Wrapf(err, "failed to get system cert pool")
				return err
			}

			if lc.CACertificate != nil {
				ok := rootCAs.AppendCertsFromPEM(lc.CACertificate)
				if !ok {
					err = errors.New("Failed to add scribd root cert to system CA bundle")
					return err
				}
			}

			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
				RootCAs:            rootCAs,
			}

			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
			}
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				err = errors.Wrapf(err, "failed to connect to the server")
				return err
			}

			err = l.StartTLS(config)
			if err != nil {
				err = errors.Wrapf(err, "failed to STARTTLS")
				return err
			}
		}

		lc.Conn = l
	}
	return err
}

// Close closes the ldap backend connection.
func (lc *SimpleLdapClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// Bind binds as the configured user
func (lc *SimpleLdapClient) Bind() (err error) {
	err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
	if err != nil {
		err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
		return err
	}
	return err
}

// Authenticate authenticates the user against the ldap backend and returns user info from the directory.
func (lc *SimpleLdapClient) Authenticate(username, password string) (success bool, userInfo map[string]string, err error) {
	err = lc.Connect()
	if err != nil {
		return false, nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(USER_FILTER, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN

	for _, attr := range lc.Attributes {
		userInfo[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return false, userInfo, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, userInfo, err
		}
	}

	return true, userInfo, nil
}

// GetGroupsOfUser returns the group for a user.
func (lc *SimpleLdapClient) GroupsForUsername(username string) (groups []string, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return groups, err
		}

		defer lc.Close()
	}
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(memberUid=%s)", username),
		[]string{"cn"}, // can it be something else than "cn"?
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	groups = []string{}
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}

	return groups, err
}

// EmailForUsername returns the Email address for the user given
func (lc *SimpleLdapClient) EmailForUsername(username string) (email string, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return email, err
		}

		defer lc.Close()
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(USER_FILTER, username),
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		err = errors.Wrap(err, "failed to perform ldap search")
		return email, err
	}

	results := []string{}
	for _, entry := range sr.Entries {
		results = append(results, entry.GetAttributeValue("mail"))
	}

	if len(results) > 0 {
		email = results[0]
		return email, err
	}

	err = errors.New("Search Failed to return anything.")
	return email, err
}

// UserChangePassword binds as the user, and changes their password.  Then binds as Admin and changes the password aging value (which they can't change themselves)
func (lc *SimpleLdapClient) UserChangePassword(username string, oldpassword string, newpassword string, adminPassword string) (err error) {
	err = lc.Connect()
	if err != nil {
		err = errors.Wrap(err, "Error in initial connection")
		return err
	}

	userDN := lc.UserDN(username)

	err = lc.Conn.Bind(userDN, oldpassword)

	if err != nil {
		err = errors.Wrap(err, "Error binding as user")
		return err
	}

	req := ldap.NewPasswordModifyRequest("", oldpassword, newpassword)
	_, err = lc.Conn.PasswordModify(req)
	if err != nil {
		err = errors.Wrap(err, "Could not change password.")
		return err
	}

	lc.Close()

	err = lc.Connect()
	if err != nil {
		err = errors.Wrap(err, "Error reconnecting as admin")
		return err
	}

	err = lc.Conn.Bind(lc.AdminDn(), adminPassword)

	if err != nil {
		err = errors.Wrap(err, "Error binding as admin to change password age")
		return err
	}

	days := DaysSinceEpoch()
	req2 := ldap.NewModifyRequest(userDN)
	req2.Replace("shadowLastChange", []string{strconv.Itoa(int(days))})
	err = lc.Conn.Modify(req2)
	if err != nil {
		err = errors.Wrap(err, "Failed to update password age")
	}

	lc.Conn.Close()
	return err

}

// AdminChangePassword performs a password change via the admin creds, and also sets the shadowLastChange attribute, which a user cannot change for themselves.
func (lc *SimpleLdapClient) AdminChangePassword(username string, newpassword string, adminPassword string) (err error) {
	err = lc.Connect()
	if err != nil {
		return err
	}

	userDN := lc.UserDN(username)

	err = lc.Conn.Bind(lc.AdminDn(), adminPassword)

	if err != nil {
		return err
	}
	req := ldap.NewPasswordModifyRequest(userDN, "", newpassword)

	_, err = lc.Conn.PasswordModify(req)
	if err != nil {
		err = errors.Wrap(err, "Could not change password")
	}

	days := DaysSinceEpoch()
	req2 := ldap.NewModifyRequest(userDN)
	req2.Replace("shadowLastChange", []string{strconv.Itoa(int(days))})
	err = lc.Conn.Modify(req2)
	if err != nil {
		err = errors.Wrap(err, "Failed to update password age")
	}

	lc.Close()

	return err
}

// PubkeyForUsername returns the SSH public key for the user from teh directory
func (lc *SimpleLdapClient) PubkeyForUsername(username string) (pubkey string, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrapf(err, "failed to connect to ldap")
			return pubkey, err
		}

		defer lc.Close()
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(USER_FILTER, username),
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return pubkey, err
	}

	results := []string{}
	for _, entry := range sr.Entries {
		results = append(results, entry.GetAttributeValue("sshPublicKey"))
	}

	if len(results) > 0 {
		return results[0], nil
	} else {
		err = errors.New("Search Failed to return anything.")
		return pubkey, err
	}
}

// UploadPubkey  Uploads a public key for a user to the directory.
func (lc *SimpleLdapClient) UploadPubkey(username string, password string, pubkeyString string) (err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			return err
		}

		defer lc.Close()
	}

	userDN := lc.UserDN(username)

	err = lc.Conn.Bind(userDN, password)

	if err != nil {
		return err
	}
	req := ldap.NewModifyRequest(userDN)
	req.Replace("sshPublicKey", []string{pubkeyString})

	err = lc.Conn.Modify(req)

	return err
}

// AddGroup adds a posix group to the directory
func (lc *SimpleLdapClient) AddGroup(groupname string, gid int) (err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return err
		}

		defer lc.Close()
	}

	dn := lc.GroupDN(groupname)

	r := ldap.NewAddRequest(dn)

	r.Attribute("objectClass", []string{"posixGroup", "top"})
	r.Attribute("cn", []string{groupname})
	r.Attribute("gidNumber", []string{strconv.Itoa(gid)})

	err = lc.Conn.Add(r)
	if err != nil {
		err = errors.Wrapf(err, "Failed to add %s to ldap", dn)
		return err
	}

	return err
}

// ModGroup changes attributes of a group.  Namely gid.
func (lc *SimpleLdapClient) ModGroup(name string, gid int) (err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return err
		}

		defer lc.Close()
	}

	dn := lc.GroupDN(name)

	r := ldap.NewModifyRequest(dn)
	r.Replace("gidNumber", []string{strconv.Itoa(gid)})
	err = lc.Conn.Modify(r)
	if err != nil {
		err = errors.Wrapf(err, "failed to modify gid of group %s", name)
		return err
	}

	return err
}

// GroupExists returns true or false depending on whether a group of this name exists in the directory
func (lc *SimpleLdapClient) GroupExists(groupname string) (ok bool, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return ok, err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return ok, err
		}

		defer lc.Close()
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(GROUP_FILTER, groupname),
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		err = errors.Wrap(err, "failed to perform ldap search")
		return ok, err
	}

	results := []string{}
	for _, entry := range sr.Entries {
		results = append(results, entry.GetAttributeValue("cn"))
	}

	if len(results) > 0 {
		ok = true
		return ok, err
	}

	return ok, err

}

// AddUserToGroup adds the username given to the group indicated.
func (lc *SimpleLdapClient) AddUserToGroup(username, groupname string) (err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return err
		}

		defer lc.Close()
	}

	dn := fmt.Sprintf("cn=%s,ou=group,%s", groupname, lc.Base)

	req := ldap.NewModifyRequest(dn)

	partial := ldap.PartialAttribute{
		Type: "memberUid",
		Vals: []string{username},
	}

	partials := make([]ldap.PartialAttribute, 0)
	partials = append(partials, partial)

	req.AddAttributes = partials

	err = lc.Conn.Modify(req)

	return err
}

// UserInGroup returns true or false depending on whether the user given is in the group indicated.
func (lc *SimpleLdapClient) UserInGroup(username, groupname string) (ok bool, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return ok, err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return ok, err
		}

		defer lc.Close()
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(cn=%s)(objectClass=posixGroup)(memberUid=%s))", groupname, username),
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		err = errors.Wrap(err, "failed to perform ldap search")
		return ok, err
	}

	if len(sr.Entries) > 0 {
		results := sr.Entries[0].GetAttributeValues("memberUid")

		ok = StringInSlice(username, results)

		return ok, err
	}

	return ok, err
}

// RemoveUserFromGroup Removes a user from a group
func (lc *SimpleLdapClient) RemoveUserFromGroup(username, groupname string) (err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return err
		}

		defer lc.Close()
	}

	dn := lc.GroupDN(groupname)

	req := ldap.NewModifyRequest(dn)

	req.Delete("memberUid", []string{username})

	err = lc.Conn.Modify(req)

	return err
}

// RemoveGroup removes a group from the directory
func (lc *SimpleLdapClient) RemoveGroup(groupname string) (err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return err
		}

		defer lc.Close()
	}

	dn := lc.GroupDN(groupname)

	req := ldap.NewDelRequest(dn, nil)
	err = lc.Conn.Del(req)

	return err
}

// GroupDn returns the GroupDN in a regular fashion
func (lc *SimpleLdapClient) GroupDN(groupname string) (dn string) {
	dn = fmt.Sprintf("cn=%s,ou=group,%s", groupname, lc.Base)

	return dn
}

// UserDn returns the UserDN in a regular fashion
func (lc *SimpleLdapClient) UserDN(username string) (dn string) {
	dn = fmt.Sprintf("uid=%s,ou=users,%s", username, lc.Base)

	return dn
}

// GroupFilterString returns a standard group filter
func (lc *SimpleLdapClient) GroupFilterString(groupname string) (filter string) {
	filter = fmt.Sprintf("(&(cn=%s)(objectClass=posixGroup))", groupname)
	return filter
}

// AddUser adds a user to the directory.  Also adds a group of the same name, and adds that user to the group
func (lc *SimpleLdapClient) AddUser(info UserInfo) (err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return err
		}

		defer lc.Close()
	}

	err = lc.AddGroup(info.UID, info.GidNumber)
	if err != nil {
		err = errors.Wrapf(err, "failed to add group %s to ldap", info.UID)
	}

	r := ldap.NewAddRequest(info.DN)
	r.Attribute("objectClass", []string{"inetOrgPerson", "person", "ldapPublicKey", "posixAccount", "top", "shadowAccount"})
	r.Attribute("uid", []string{info.UID})
	r.Attribute("loginShell", []string{info.Shell})
	r.Attribute("uidNumber", []string{strconv.Itoa(info.UidNumber)})
	r.Attribute("gidNumber", []string{strconv.Itoa(info.GidNumber)})
	r.Attribute("cn", []string{info.CN})
	r.Attribute("sn", []string{info.SN})
	r.Attribute("homeDirectory", []string{info.HomeDir})
	r.Attribute("mail", []string{info.Email})
	r.Attribute("shadowLastChange", []string{"10000"})
	r.Attribute("shadowMax", []string{"9999"})
	r.Attribute("shadowWarning", []string{"7"})
	r.Attribute("sshPublicKey", []string{info.PubKey})

	err = lc.Conn.Add(r)
	if err != nil {
		err = errors.Wrapf(err, "failed to add user %s to ldap", info.UID)
		return err
	}

	err = lc.AddUserToGroup(info.UID, info.UID)
	if err != nil {
		err = errors.Wrapf(err, "failed to add user %s to group %s", info.UID, info.UID)
	}

	return err
}

// ModUser modifies an existing user with new attributes
func (lc *SimpleLdapClient) ModUser(info UserInfo) (err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return err
		}

		defer lc.Close()
	}

	r := ldap.NewModifyRequest(info.DN)
	r.Replace("loginShell", []string{info.Shell})
	r.Replace("uidNumber", []string{strconv.Itoa(info.UidNumber)})
	r.Replace("gidNumber", []string{strconv.Itoa(info.GidNumber)})
	r.Replace("cn", []string{info.CN})
	r.Replace("sn", []string{info.SN})
	r.Replace("homeDirectory", []string{info.HomeDir})
	r.Replace("mail", []string{info.Email})
	r.Replace("sshPublicKey", []string{info.PubKey})

	err = lc.Conn.Modify(r)
	if err != nil {
		err = errors.Wrapf(err, "failed to modify user %s", info.UID)
		return err
	}

	return err
}

// GetUser gets a user by name and returns a UserInfo object
func (lc *SimpleLdapClient) GetUser(name string) (info UserInfo, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return info, err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return info, err
		}

		defer lc.Close()
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(USER_FILTER, name),
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		err = errors.Wrap(err, "failed to perform ldap search")
		return info, err
	}

	if len(sr.Entries) > 0 {
		entry := sr.Entries[0]

		info.UID = entry.GetAttributeValue("uid")
		info.Shell = entry.GetAttributeValue("loginShell")
		info.CN = entry.GetAttributeValue("cn")
		info.SN = entry.GetAttributeValue("sn")
		info.HomeDir = entry.GetAttributeValue("homeDirectory")
		info.Email = entry.GetAttributeValue("mail")
		info.PubKey = entry.GetAttributeValue("sshPublicKey")
		info.DN = lc.UserDN(name)

		uid, _ := strconv.Atoi(entry.GetAttributeValue("uidNumber"))
		info.UidNumber = uid

		gid, _ := strconv.Atoi(entry.GetAttributeValue("gidNumber"))
		info.GidNumber = gid

		lastChange, _ := strconv.Atoi(entry.GetAttributeValue("shadowLastChange"))
		info.ShadowLastChange = lastChange
	} else {
		err = errors.Wrapf(err, "uiser %s not found in directory", name)
		return info, err
	}

	return info, err
}

// GetGroup gets a user by name and returns a UserInfo object
func (lc *SimpleLdapClient) GetGroup(name string) (gid int, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return gid, err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return gid, err
		}

		defer lc.Close()
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(GROUP_FILTER, name),
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		err = errors.Wrap(err, "failed to perform ldap search")
		return gid, err
	}

	if len(sr.Entries) > 0 {
		entry := sr.Entries[0]

		num, _ := strconv.Atoi(entry.GetAttributeValue("gidNumber"))

		gid = num

	} else {
		err = errors.Wrapf(err, "group %s not found in directory", name)
		return gid, err
	}

	return gid, err
}

// RemoveUser removes a user, and the group of the same name as well.
func (lc *SimpleLdapClient) RemoveUser(username string) (err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return err
		}

		defer lc.Close()
	}

	dn := lc.UserDN(username)

	req := ldap.NewDelRequest(dn, nil)
	err = lc.Conn.Del(req)
	if err != nil {
		err = errors.Wrapf(err, "failed removing user %s", username)
		return err
	}

	dn = lc.GroupDN(username)
	req = ldap.NewDelRequest(dn, nil)
	err = lc.Conn.Del(req)
	if err != nil {
		err = errors.Wrapf(err, "failed removing group %s", username)
		return err
	}

	return err
}

// UserExists
func (lc *SimpleLdapClient) UserExists(username string) (ok bool, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return ok, err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return ok, err
		}

		defer lc.Close()
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(USER_FILTER, username),
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		err = errors.Wrap(err, "failed to perform ldap search")
		return ok, err
	}

	results := []string{}
	for _, entry := range sr.Entries {
		results = append(results, entry.GetAttributeValue("cn"))
	}

	if len(results) > 0 {
		ok = true
		return ok, err
	}

	return ok, err

}

// UnixGroupNames fetches a list of unix group names in the directory
func (lc *SimpleLdapClient) UnixGroupNames() (names []string, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return names, err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return names, err
		}

		defer lc.Close()
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=posixGroup)",
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		err = errors.Wrap(err, "failed to perform ldap search")
		return names, err
	}

	names = make([]string, 0)
	for _, entry := range sr.Entries {
		names = append(names, entry.GetAttributeValue("cn"))
	}

	return names, err
}

// UserNames fetches a list of user names in the directory
func (lc *SimpleLdapClient) UserNames() (names []string, err error) {
	if lc.Conn == nil {
		err = lc.Connect()
		if err != nil {
			err = errors.Wrap(err, "failed to connect to ldap")
			return names, err
		}

		err = lc.Bind()
		if err != nil {
			err = errors.Wrapf(err, "failed to bind as %s", lc.BindDN)
			return names, err
		}

		defer lc.Close()
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=person)",
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		err = errors.Wrap(err, "failed to perform ldap search")
		return names, err
	}

	names = make([]string, 0)
	for _, entry := range sr.Entries {
		names = append(names, entry.GetAttributeValue("uid"))
	}

	return names, err
}
