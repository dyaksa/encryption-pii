package helper

import (
	"regexp"
	"strings"
)

func Split(value string, sep string) (s []string) {
	regex := regexp.MustCompile(sep)
	parts := strings.Split(value, sep)
	for _, part := range parts {
		matches := regex.FindAllString(part, -1)
		s = append(s, matches...)
	}
	return
}
