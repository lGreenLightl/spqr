
package shgoparser

type Show struct {
	Cmd string
}

// The frollowing constants represent SHOW statements.
const (
	ShowDatabasesStr     = "databases"
	ShowPoolsStr         = "pools"
	ShowUnsupportedStr   = "unsupported"
)
