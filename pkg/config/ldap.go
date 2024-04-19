package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type LDAPAuthMode string

const (
	SimpleBindMode    = LDAPAuthMode("simple_bind")
	SearchAndBindMode = LDAPAuthMode("search_and_bind")
)

var (
	ErrServerConn   = errors.New("there are no ldap servers available or such servers don't exist")
	ErrSearchResult = errors.New("too many entries returned or user doesn't exist")
)

type LDAPConfig struct {
	Mode LDAPAuthMode `json:"ldap_auth_mode" yaml:"ldap_auth_mode" toml:"ldap_auth_mode"`

	Scheme       string   `json:"scheme" yaml:"scheme" toml:"scheme"`
	TLS          bool     `json:"tls" yaml:"tls" toml:"tls"`
	RootCertFile string   `json:"root_cert_file" yaml:"root_cert_file" toml:"root_cert_file"`
	Servers      []string `json:"servers" yaml:"servers" toml:"servers"`
	Port         string   `json:"port" yaml:"port" toml:"port"`

	Prefix string `json:"prefix" yaml:"prefix" toml:"prefix"`
	Suffix string `json:"suffix" yaml:"suffix" toml:"suffix"`

	BindDN          string `json:"bind_dn" yaml:"bind_dn" toml:"bind_dn"`
	BindPassword    string `json:"bind_password" yaml:"bind_password" toml:"bind_password"`
	BaseDN          string `json:"base_dn" yaml:"base_dn" toml:"base_dn"`
	SearchAttribute string `json:"search_attribute" yaml:"search_attribute" toml:"search_attribute"`
	SearchFilter    string `json:"search_filter" yaml:"search_filter" toml:"search_filter"`
}

func (l *LDAPConfig) ServerConn() (*ldap.Conn, string, error) {
	for _, server := range l.Servers {
		conn, err := ldap.DialURL(l.ldapUrl(server))
		if err != nil {
			continue
		}

		return conn, server, nil
	}

	return nil, "", ErrServerConn
}

func (l *LDAPConfig) StartTLS(conn *ldap.Conn, server string) error {
	caCert, err := os.ReadFile(l.RootCertFile)
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	err = conn.StartTLS(&tls.Config{
		ServerName: server,
		RootCAs:    caCertPool,
	})
	if err != nil {
		return err
	}

	return nil
}

func (l *LDAPConfig) Bind(conn *ldap.Conn, username string, password string) error {
	err := conn.Bind(l.ldapUsername(username), password)
	if err != nil {
		return err
	}

	return nil
}

func (l *LDAPConfig) SearchBind(conn *ldap.Conn) error {
	var err error

	if l.BindDN == "" || l.BindPassword == "" {
		err = conn.UnauthenticatedBind("")
	} else {
		err = l.Bind(conn, l.BindDN, l.BindPassword)
	}
	if err != nil {
		return err
	}

	return nil
}

func (l *LDAPConfig) ModifySearchAttribute() string {
	switch l.SearchAttribute {
	case "":
		return "uid"
	default:
		return l.SearchAttribute
	}
}

func (l *LDAPConfig) ModifySearchFilter(searchAttribute string, username string) string {
	switch l.SearchFilter {
	case "":
		return fmt.Sprintf("(%s=%s)", l.SearchAttribute, ldap.EscapeFilter(username))
	default:
		return strings.ReplaceAll(l.SearchFilter, "$username", ldap.EscapeFilter(username))
	}
}

func (l *LDAPConfig) DoSearchRequest(conn *ldap.Conn, searchFilter string) (*ldap.SearchResult, error) {
	searchRequest := ldap.NewSearchRequest(
		l.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		searchFilter,
		[]string{"dn"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	return searchResult, nil
}

func (l *LDAPConfig) CheckSearchResult(entries []*ldap.Entry) error {
	if len(entries) != 1 {
		return ErrSearchResult
	}

	return nil
}

func (l *LDAPConfig) ldapUrl(server string) string {
	return fmt.Sprintf("%s://%s:%s", l.Scheme, server, l.Port)
}

func (l *LDAPConfig) ldapUsername(username string) string {
	return fmt.Sprintf("%s%s%s", l.Prefix, username, l.Suffix)
}
