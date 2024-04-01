package config

type LDAPAuthMode string

const (
	SimpleBindMode    = LDAPAuthMode("simple_bind")
	SearchAndBindMode = LDAPAuthMode("search_and_bind")
)

type LDAPCfg struct {
	Mode            LDAPAuthMode `json:"auth_mode" yaml:"auth_mode" toml:"auth_mode"`
	Scheme          string       `json:"scheme" yaml:"scheme" toml:"scheme"`
	TLS             bool         `json:"tls" yaml:"tls" toml:"tls"`
	Server          string       `json:"server" yaml:"server" toml:"server"`
	Port            int          `json:"port" yaml:"port" toml:"port"`
	Prefix          string       `json:"prefix" yaml:"prefix" toml:"prefix"`
	Suffix          string       `json:"suffix" yaml:"suffix" toml:"suffix"`
	BindDN          string       `json:"bind_dn" yaml:"bind_dn" toml:"bind_dn"`
	BindPassword    string       `json:"bind_pwd" yaml:"bind_pwd" toml:"bind_pwd"`
	BaseDN          string       `json:"base_dn" yaml:"base_dn" toml:"base_dn"`
	SearchAttribute string       `json:"search_attr" yaml:"search_attr" toml:"search_attr"`
	SearchFilter    string       `json:"search_filter" yaml:"search_filter" toml:"search_filter"`
}
