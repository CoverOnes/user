// Package identity validates Taiwan national-ID and legal-name input for the
// real-name register flow.
//
// SOURCE OF TRUTH: the TW national-ID checksum algorithm, the letter→code table,
// the digit weights, and the legal-name rules are COPIED VERBATIM from the kyc
// service's canonical implementation at
//
//	/Users/waynechen/_project/coverones/kyc/internal/service/validate.go
//	(twNationalIDPattern / twLetterCodes / twDigitWeights /
//	 validateTWNationalID / validateLegalName)
//
// Per the SA spec this is a deliberate copy (NOT a shared module): the two
// services version their identity rules independently. If the MOI specification
// or the kyc rules change, update kyc first (source of truth) then mirror here.
package identity

import (
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/CoverOnes/user/internal/domain"
)

// twNationalIDPattern validates a Taiwan national ID structure: 1 letter +
// 1 gender digit (1=male, 2=female) + 8 digits. Structure only — the checksum
// (ValidateTWNationalID) is the authoritative gate.
var twNationalIDPattern = regexp.MustCompile(`^[A-Z][12]\d{8}$`)

// twLetterCodes maps the leading area letter of a Taiwan national ID to its
// official two-digit numeric code (A=10, B=11, ... per the MOI specification —
// NOT a naive A=10..Z=35; I=34, O=35, etc. follow the published table).
var twLetterCodes = map[byte]int{
	'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15, 'G': 16, 'H': 17,
	'I': 34, 'J': 18, 'K': 19, 'L': 20, 'M': 21, 'N': 22, 'O': 35, 'P': 23,
	'Q': 24, 'R': 25, 'S': 26, 'T': 27, 'U': 28, 'V': 29, 'W': 32, 'X': 30,
	'Y': 31, 'Z': 33,
}

// twDigitWeights are the positional weights applied to the 9 trailing digits
// (gender digit + 8 body digits).
var twDigitWeights = [9]int{8, 7, 6, 5, 4, 3, 2, 1, 1}

// maxLegalNameRunes caps the legal-name length to bound storage and reject abuse.
const maxLegalNameRunes = 100

// ValidateTWNationalID verifies the Taiwan national-id checksum.
// Algorithm (MOI): letter -> two-digit code (n1,n2); checksum =
//
//	n1*1 + n2*9 + d1*8 + d2*7 + ... + d8*2 + d9*1
//
// where d1..d9 are the 9 trailing digits (gender digit + 8 body digits).
// Valid iff checksum % 10 == 0. Rejects structurally-valid-but-invalid ids
// (e.g. a real-format id whose check digit doesn't add up).
//
// The id is HIGH-sensitivity PII: this function NEVER echoes the value back in
// the returned error (only generic messages), so a national ID can never leak
// into a log line or API response via error wrapping.
func ValidateTWNationalID(id string) error {
	if !twNationalIDPattern.MatchString(id) {
		return fmt.Errorf("%w: nationalId must be a valid Taiwan national ID (1 letter + 9 digits)", domain.ErrValidation)
	}

	code, ok := twLetterCodes[id[0]]
	if !ok {
		// Unreachable given the [A-Z] pattern + full map, but fail closed.
		return fmt.Errorf("%w: nationalId has an unrecognized area letter", domain.ErrValidation)
	}

	sum := (code/10)*1 + (code%10)*9

	for i := 0; i < 9; i++ {
		digit := int(id[i+1] - '0')
		sum += digit * twDigitWeights[i]
	}

	if sum%10 != 0 {
		return fmt.Errorf("%w: nationalId checksum is invalid", domain.ErrValidation)
	}

	return nil
}

// ValidateLegalName rejects empty / over-long / control-char-bearing names.
// The name is HIGH-sensitivity PII: the returned error NEVER echoes the value.
func ValidateLegalName(name string) error {
	n := utf8.RuneCountInString(name)
	if n == 0 {
		return fmt.Errorf("%w: legalName is required", domain.ErrValidation)
	}

	if n > maxLegalNameRunes {
		return fmt.Errorf("%w: legalName must be at most %d characters", domain.ErrValidation, maxLegalNameRunes)
	}

	for _, r := range name {
		if r == '\x00' || r == '\r' || r == '\n' || (r < 0x20 && r != '\t') {
			return fmt.Errorf("%w: legalName contains invalid control characters", domain.ErrValidation)
		}
	}

	return nil
}
