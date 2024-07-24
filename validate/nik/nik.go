package nik

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dyaksa/encryption-pii/validate"
)

type NIK[T any] struct {
	v T
}

func Parse[T any](v T) (NIK[T], error) {
	switch any(v).(type) {
	case string:
		if !IsValid(any(v).(string)) {
			return NIK[T]{}, fmt.Errorf("invalid data NIK %v", v)
		}
		return NIK[T]{v: v}, nil
	default:
		return NIK[T]{}, fmt.Errorf("invalid type %T", v)
	}
}

func (n NIK[T]) Value() T {
	return n.v
}

func (n NIK[T]) ToString() string {
	validNik := regexp.MustCompile(NIK_REGEX).FindStringSubmatch(numbersOnly(n.v))
	return fmt.Sprintf("%v", strings.Join(validNik[1:], "."))
}

func (n NIK[T]) ToStringP() *string {
	validNik := regexp.MustCompile(NIK_REGEX).FindStringSubmatch(numbersOnly(n.v))
	result := fmt.Sprintf("%v", strings.Join(validNik[1:], "."))
	return &result
}

func (n NIK[T]) ToSlice() []string {
	validNik := regexp.MustCompile(NIK_REGEX).FindStringSubmatch(numbersOnly(n.v))
	return validNik[1:]
}

func IsValid(nik string) bool {
	if len(nik) != NIK_LENGTH {
		return false
	}

	if !regexp.MustCompile(NIK_REGEX).MatchString(nik) {
		return false
	}

	validNik := regexp.MustCompile(NIK_REGEX).FindStringSubmatch(numbersOnly(nik))
	if validNik == nil {
		return false
	}

	// validProvince := includes(convertProvinceDataToBoolMap(validate.PROVINCE_DATA), validNik[1])
	// if !validProvince {
	// 	return false
	// }

	cBirthday := reformatBirthday(validNik[4])

	_, err := formatDate("19" + cBirthday)
	validBirthday := err == nil

	// return validProvince && validBirthday
	return validBirthday
}

func includes(array map[string]bool, key string) bool {
	_, found := array[key]
	return found
}

func convertProvinceDataToBoolMap(data map[string]validate.ProvinceData) map[string]bool {
	boolMap := make(map[string]bool)
	for key := range data {
		boolMap[key] = true
	}
	return boolMap
}

func numbersOnly(v interface{}) (value string) {
	input := fmt.Sprintf("%v", v)

	re := regexp.MustCompile(`[^\d]`)
	value = re.ReplaceAllString(input, "")
	return
}

func formatDate(dateStr string) (time.Time, error) {
	return time.Parse("20060102", dateStr)
}

func reformatBirthday(datePart string) string {
	if len(datePart) == 6 {
		day := datePart[:2]
		month := datePart[2:4]
		year := datePart[4:6]
		return fmt.Sprintf("%s%s%s", year, month, day)
	}
	return ""
}
