package lib

import "strings"

func Sanitize(s string) string {
	s = strings.Replace(s, "/", "_", -1)
	s = strings.Replace(s, "=", "_", -1)
	return s
}
