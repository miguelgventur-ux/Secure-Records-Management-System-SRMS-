package main

import "unicode/utf8"

func validatePhone(s string) bool {
	return s == "" || phoneRegex.MatchString(s)
}

type validationErrors []string

func runeLen(s string) int { return utf8.RuneCountInString(s) }
