package npwp

import (
	"fmt"
	"regexp"
	"strings"
)

type NPWP[T any] struct {
	v T
}

func Parse[T any](v T) (NPWP[T], error) {
	switch any(v).(type) {
	case string:
		if !IsValid(any(v).(string)) {
			return NPWP[T]{}, fmt.Errorf("invalid data NPWP %v", v)
		}
		return NPWP[T]{v: v}, nil
	default:
		return NPWP[T]{}, fmt.Errorf("invalid type %T", v)
	}
}

func (n NPWP[T]) Value() T {
	return n.v
}

func (n NPWP[T]) ToString() string {
	validNpwp := regexp.MustCompile(NPWP_REGEX).FindStringSubmatch(numbersOnly(n.v))
	return fmt.Sprintf("%v", strings.Join(validNpwp[1:], "."))
}

func (n NPWP[T]) ToStringP() *string {
	validNpwp := regexp.MustCompile(NPWP_REGEX).FindStringSubmatch(numbersOnly(n.v))
	result := fmt.Sprintf("%v", strings.Join(validNpwp[1:], "."))
	return &result
}

func (n NPWP[T]) ToSlice() []string {
	validNpwp := regexp.MustCompile(NPWP_REGEX).FindStringSubmatch(numbersOnly(n.v))
	return validNpwp[1:]
}

func IsValid(npwp string) bool {
	if len(npwp) != NPWP_LENGTH {
		return false
	}

	if !regexp.MustCompile(NPWP_REGEX).MatchString(npwp) {
		return false
	}

	validNpwp := regexp.MustCompile(NPWP_REGEX).FindStringSubmatch(numbersOnly(npwp))
	if validNpwp == nil {
		return false
	}

	return isValidTaxIdentity(validNpwp[1])
}

func includes(array map[string]bool, key string) bool {
	_, found := array[key]
	return found
}

func numbersOnly(v interface{}) (value string) {
	input := fmt.Sprintf("%v", v)

	re := regexp.MustCompile(`[^\d]`)
	value = re.ReplaceAllString(input, "")
	return
}

func convertTaxIdentityDataToBoolMap(data []string) map[string]bool {
	boolMap := make(map[string]bool)
	for _, k := range data {
		boolMap[k] = true
	}
	return boolMap
}

func isValidTaxIdentity(texIdentity string) bool {
	return includes(convertTaxIdentityDataToBoolMap(NPWP_TAX_IDENTITIES), texIdentity)
}
