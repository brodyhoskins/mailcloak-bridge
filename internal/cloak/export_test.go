package cloak

import "github.com/emersion/go-imap/v2"

// Refusal is the error Authorize refuses a login with, with text.
func Refusal(text string) error { return refusal{&imap.Error{Text: text}} }
