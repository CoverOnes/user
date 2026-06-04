package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// totpPeriodSeconds is the TOTP step size (RFC 6238 default, Google-Authenticator
	// compatible).
	totpPeriodSeconds = 30

	// totpSkewSteps is the ±N-step validation window. 1 means the code from the
	// previous, current, and next 30-second window all validate — the standard skew
	// that tolerates modest clock drift without widening the brute-force surface.
	totpSkewSteps = 1

	// totpSecretSizeBytes is the random secret size (160 bits) — comfortably above
	// the RFC 4226 80-bit minimum and what Google Authenticator expects.
	totpSecretSizeBytes = 20

	// backupCodeCount is how many one-time backup codes are minted at confirm.
	backupCodeCount = 10

	// backupCodeBytes is the entropy per backup code (80 bits → 16 base32 chars).
	backupCodeBytes = 10

	// totpCodeDigits is the expected length of a submitted TOTP passcode.
	totpCodeDigits = 6
)

// base32NoPad encodes backup codes (uppercase A-Z2-7, no padding) so they are easy
// to read and type. It is NOT the TOTP secret encoder (that is handled by the otp lib).
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// MFAService implements the TOTP 2FA primitives (enroll / confirm / verify /
// disable). It is deliberately NOT wired into the login flow in this increment —
// the login path is unchanged and enforcement is a later, flag-gated step.
//
// The TOTP secret and backup-code hashes are encrypted at rest with the SAME
// Encryptor that protects the other PII columns; the plaintext secret is returned
// exactly once (at enroll, for the QR / manual entry) and the raw backup codes
// exactly once (at confirm). Neither is ever logged.
type MFAService struct {
	users     store.UserStore
	encryptor Encryptor
	issuer    string
	now       func() time.Time
}

// NewMFAService builds an MFAService. issuer is the otpauth issuer label (config
// USER_TOTP_ISSUER); encryptor MUST be non-nil (the secret is never stored in the
// clear). now defaults to time.Now and is overridable in tests.
func NewMFAService(users store.UserStore, encryptor Encryptor, issuer string) *MFAService {
	return &MFAService{
		users:     users,
		encryptor: encryptor,
		issuer:    issuer,
		now:       time.Now,
	}
}

// EnrollOutput is returned by Enroll. The secret is base32 (manual entry) and the
// otpauth URI feeds a QR code. Both are returned ONCE; MFA is not yet enabled.
type EnrollOutput struct {
	// OtpauthURI is the otpauth://totp/... provisioning URI for QR rendering.
	OtpauthURI string
	// Secret is the base32-encoded TOTP secret for manual entry.
	Secret string
}

// Enroll generates a fresh TOTP secret for the user, stores it ENCRYPTED as the
// pending secret (mfa_enabled stays false), and returns the provisioning URI plus
// the base32 secret. Re-enrolling overwrites a prior pending secret. An already
// mfa-enabled user must disable first (ErrMFAAlreadyEnabled).
func (s *MFAService) Enroll(ctx context.Context, userID uuid.UUID) (*EnrollOutput, error) {
	if s.encryptor == nil {
		return nil, errors.New("mfa: encryptor not configured")
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if u.MFAEnabled {
		return nil, domain.ErrMFAAlreadyEnabled
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: u.Email,
		Period:      totpPeriodSeconds,
		SecretSize:  totpSecretSizeBytes,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // Google-Authenticator compatible
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	secret := key.Secret()

	secretEnc, err := s.encryptor.Encrypt(secret)
	if err != nil {
		// The error from the Encryptor never contains the plaintext (see pii.Encrypt).
		return nil, fmt.Errorf("encrypt totp secret: %w", err)
	}

	if err := s.users.SetPendingTOTPSecret(ctx, userID, secretEnc); err != nil {
		return nil, err
	}

	return &EnrollOutput{
		OtpauthURI: key.URL(),
		Secret:     secret,
	}, nil
}

// ConfirmOutput is returned by Confirm. BackupCodes are the raw one-time codes,
// shown to the user EXACTLY ONCE (only the hashes are persisted).
type ConfirmOutput struct {
	BackupCodes []string
}

// Confirm verifies the submitted code against the user's PENDING secret with the
// standard ±1-step skew. On success it enables MFA, mints + stores (hashed,
// encrypted) one-time backup codes, and returns the raw codes once. A wrong code
// returns ErrInvalidTOTPCode; no pending secret returns ErrMFANotEnrolled.
func (s *MFAService) Confirm(ctx context.Context, userID uuid.UUID, code string) (*ConfirmOutput, error) {
	if s.encryptor == nil {
		return nil, errors.New("mfa: encryptor not configured")
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if u.MFAEnabled {
		return nil, domain.ErrMFAAlreadyEnabled
	}

	if len(u.TOTPSecretEnc) == 0 {
		return nil, domain.ErrMFANotEnrolled
	}

	secret, err := s.encryptor.Decrypt(u.TOTPSecretEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt pending totp secret: %w", err)
	}

	ok, err := validateTOTP(strings.TrimSpace(code), secret, s.now())
	if err != nil {
		return nil, fmt.Errorf("validate totp: %w", err)
	}
	if !ok {
		return nil, domain.ErrInvalidTOTPCode
	}

	rawCodes, hashesJSON, err := generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("generate backup codes: %w", err)
	}

	codesEnc, err := s.encryptor.Encrypt(hashesJSON)
	if err != nil {
		return nil, fmt.Errorf("encrypt backup codes: %w", err)
	}

	if err := s.users.EnableMFA(ctx, userID, codesEnc, s.now().UTC()); err != nil {
		return nil, err
	}

	return &ConfirmOutput{BackupCodes: rawCodes}, nil
}

// Verify validates a TOTP code for an mfa-ENABLED user. This is the primitive a
// future login step will call; it is NOT called from login in this increment.
// Returns nil on a valid code, ErrInvalidTOTPCode on an invalid one, and
// ErrMFANotEnrolled when MFA is not enabled.
func (s *MFAService) Verify(ctx context.Context, userID uuid.UUID, code string) error {
	if s.encryptor == nil {
		return errors.New("mfa: encryptor not configured")
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if !u.MFAEnabled || len(u.TOTPSecretEnc) == 0 {
		return domain.ErrMFANotEnrolled
	}

	secret, err := s.encryptor.Decrypt(u.TOTPSecretEnc)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	ok, err := validateTOTP(strings.TrimSpace(code), secret, s.now())
	if err != nil {
		return fmt.Errorf("validate totp: %w", err)
	}
	if !ok {
		return domain.ErrInvalidTOTPCode
	}

	return nil
}

// Disable turns MFA off for an mfa-enabled user AFTER verifying a current TOTP code
// (or a still-unused backup code). It clears the secret, the backup codes, and the
// enrolled-at stamp. ErrMFANotEnrolled when MFA is not enabled; ErrInvalidTOTPCode
// when neither the TOTP code nor a backup code matches.
func (s *MFAService) Disable(ctx context.Context, userID uuid.UUID, code string) error {
	if s.encryptor == nil {
		return errors.New("mfa: encryptor not configured")
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if !u.MFAEnabled || len(u.TOTPSecretEnc) == 0 {
		return domain.ErrMFANotEnrolled
	}

	trimmed := strings.TrimSpace(code)

	secret, err := s.encryptor.Decrypt(u.TOTPSecretEnc)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	ok, err := validateTOTP(trimmed, secret, s.now())
	if err != nil {
		return fmt.Errorf("validate totp: %w", err)
	}

	if !ok {
		// Fall back to a backup code so a user who lost their authenticator can still
		// turn MFA off. matchBackupCode is constant-time per candidate.
		matched, matchErr := s.matchBackupCode(u, trimmed)
		if matchErr != nil {
			return matchErr
		}
		if !matched {
			return domain.ErrInvalidTOTPCode
		}
	}

	return s.users.DisableMFA(ctx, userID)
}

// matchBackupCode reports whether the submitted code matches one of the user's
// stored (hashed) backup codes. Comparison is constant-time. It does NOT consume
// the code here — Disable clears every code immediately after, so single-use is
// guaranteed by the wipe.
func (s *MFAService) matchBackupCode(u *domain.User, code string) (bool, error) {
	if len(u.MFABackupCodesEnc) == 0 || code == "" {
		return false, nil
	}

	hashesJSON, err := s.encryptor.Decrypt(u.MFABackupCodesEnc)
	if err != nil {
		return false, fmt.Errorf("decrypt backup codes: %w", err)
	}

	var hashes []string
	if err := json.Unmarshal([]byte(hashesJSON), &hashes); err != nil {
		return false, fmt.Errorf("unmarshal backup codes: %w", err)
	}

	want := hashBackupCode(code)
	matched := false
	for _, h := range hashes {
		// Constant-time compare every candidate (no early return) to avoid leaking
		// which position matched via timing.
		if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			matched = true
		}
	}

	return matched, nil
}

// validateTOTP wraps totp.ValidateCustom with the project's fixed period / digits /
// skew so every call site uses the identical parameters.
func validateTOTP(code, secret string, t time.Time) (bool, error) {
	if len(code) != totpCodeDigits {
		// Reject the obviously-malformed length before the HMAC work; a wrong length
		// can never be a valid 6-digit code.
		return false, nil
	}

	return totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
		Period:    totpPeriodSeconds,
		Skew:      totpSkewSteps,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// generateBackupCodes mints backupCodeCount random codes and returns (rawCodes,
// jsonArrayOfHashes). Only the hashes are persisted; the raw codes are returned to
// the caller once.
func generateBackupCodes() (raw []string, hashesJSON string, err error) {
	raw = make([]string, 0, backupCodeCount)
	hashes := make([]string, 0, backupCodeCount)

	for range backupCodeCount {
		buf := make([]byte, backupCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, "", fmt.Errorf("read backup code entropy: %w", err)
		}

		code := base32NoPad.EncodeToString(buf)
		raw = append(raw, code)
		hashes = append(hashes, hashBackupCode(code))
	}

	encoded, err := json.Marshal(hashes)
	if err != nil {
		return nil, "", fmt.Errorf("marshal backup code hashes: %w", err)
	}

	return raw, string(encoded), nil
}

// hashBackupCode returns the lowercase hex SHA-256 of a backup code. Backup codes
// are high-entropy random values (not user-chosen passwords), so a single SHA-256
// is sufficient — there is nothing to brute-force offline.
func hashBackupCode(code string) string {
	sum := sha256.Sum256([]byte(code))

	return hex.EncodeToString(sum[:])
}
