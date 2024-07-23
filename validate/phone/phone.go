package phone

import (
	"fmt"
	"regexp"
	"strings"
)

type Phone[T any] struct {
	v T
}

func Parse[T any](v T) (Phone[T], error) {
	switch any(v).(type) {
	case string:
		if !IsValid(any(v).(string)) {
			return Phone[T]{}, fmt.Errorf("invalid data phone %v", v)
		}
		return Phone[T]{v: v}, nil
	default:
		return Phone[T]{}, fmt.Errorf("invalid type %T", v)
	}
}

func (p Phone[T]) Value() T {
	return p.v
}

func (p Phone[T]) ToString() string {
	validPhone := regexp.MustCompile(PHONE_REGEX).FindStringSubmatch(numbersOnly(p.v))
	return fmt.Sprintf("%v", strings.Join(validPhone[1:], "-"))
}

func (p Phone[T]) ToStringP() *string {
	validPhone := regexp.MustCompile(PHONE_REGEX).FindStringSubmatch(numbersOnly(p.v))
	result := fmt.Sprintf("%v", strings.Join(validPhone[1:], "-"))
	return &result
}

func (p Phone[T]) ToSlice() []string {
	validPhone := regexp.MustCompile(PHONE_REGEX).FindStringSubmatch(numbersOnly(p.v))
	return validPhone
}

func IsValid(phone string) bool {
	cleanNumber := strings.ReplaceAll(phone, "-", "")
	cleanNumber = strings.ReplaceAll(cleanNumber, " ", "")

	if !regexp.MustCompile(PHONE_REGEX).MatchString(cleanNumber) {
		return false
	}

	validPhone := regexp.MustCompile(PHONE_REGEX).FindStringSubmatch(numbersOnly(cleanNumber))
	if validPhone == nil {
		return false
	}

	correctPhone := correctLength(len(validPhone[0]), PHONE_MIN_LENGTH, PHONE_MAX_LENGTH)

	return correctPhone
}

func numbersOnly(v interface{}) (value string) {
	input := fmt.Sprintf("%v", v)

	re := regexp.MustCompile(`[^\d]`)
	value = re.ReplaceAllString(input, "")
	return
}

func correctLength(length int, minLength int, maxLength int) bool {
	return length >= minLength && length <= maxLength
}
