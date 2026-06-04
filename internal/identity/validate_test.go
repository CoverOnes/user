package identity_test

import (
	"strings"
	"testing"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTWNationalID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "valid canonical A123456789", id: "A123456789", wantErr: false},
		{name: "valid B100000002", id: "B100000002", wantErr: false},
		{name: "valid F223456786", id: "F223456786", wantErr: false},
		{name: "checksum invalid (last digit wrong)", id: "A123456788", wantErr: true},
		{name: "checksum invalid B234567890", id: "B234567890", wantErr: true},
		{name: "wrong gender digit (3)", id: "A323456789", wantErr: true},
		{name: "too short", id: "A12345678", wantErr: true},
		{name: "too long", id: "A1234567890", wantErr: true},
		{name: "lowercase letter rejected", id: "a123456789", wantErr: true},
		{name: "empty", id: "", wantErr: true},
		{name: "leading digit not letter", id: "1123456789", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := identity.ValidateTWNationalID(tc.id)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, domain.ErrValidation)
				// The PII value must never appear in the error message.
				if tc.id != "" {
					assert.NotContains(t, err.Error(), tc.id, "national id must not leak into the error")
				}

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestValidateLegalName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid ascii", input: "Alice Wang", wantErr: false},
		{name: "valid multibyte", input: "王小明", wantErr: false},
		{name: "valid with tab (allowed control)", input: "Alice\tWang", wantErr: false},
		{name: "exactly 100 runes", input: strings.Repeat("公", 100), wantErr: false},
		{name: "empty rejected", input: "", wantErr: true},
		{name: "over 100 runes rejected", input: strings.Repeat("x", 101), wantErr: true},
		{name: "null byte rejected", input: "Bad\x00Name", wantErr: true},
		{name: "newline rejected", input: "Bad\nName", wantErr: true},
		{name: "carriage return rejected", input: "Bad\rName", wantErr: true},
		{name: "control char rejected", input: "Bad\x07Name", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := identity.ValidateLegalName(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, domain.ErrValidation)
				// The legal name must never appear in the error message.
				if tc.input != "" {
					assert.NotContains(t, err.Error(), tc.input, "legal name must not leak into the error")
				}

				return
			}

			require.NoError(t, err)
		})
	}
}
