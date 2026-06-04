// Package mailer sends transactional email (currently: account email
// verification) over SMTP using github.com/wneessen/go-mail.
package mailer

import (
	"context"
	"fmt"
	"time"

	"github.com/wneessen/go-mail"
)

// Mailer sends transactional emails. It is an interface so the service layer can
// be tested with a spy (assert send count + recipient) without touching SMTP.
type Mailer interface {
	// SendVerification delivers an email-verification message containing the
	// (raw, single-use) token to the recipient address. It honors ctx and a
	// per-send timeout; a transport failure returns a non-nil error and the
	// caller decides whether to surface it (register does NOT — it logs and
	// returns 201 so the account is still created).
	SendVerification(ctx context.Context, to, token string) error
}

// Config carries the SMTP connection parameters.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// SendTimeout bounds a single send. Zero falls back to defaultSendTimeout.
	SendTimeout time.Duration
}

const defaultSendTimeout = 10 * time.Second

// SMTPMailer is the production Mailer backed by an SMTP server.
type SMTPMailer struct {
	cfg    Config
	client *mail.Client
}

// NewSMTPMailer constructs an SMTPMailer. The underlying client is created once
// and reused; go-mail dials lazily per DialAndSend so no connection is held open
// between sends. cfg is taken by pointer to avoid copying the struct.
func NewSMTPMailer(cfg *Config) (*SMTPMailer, error) {
	c := *cfg
	if c.SendTimeout <= 0 {
		c.SendTimeout = defaultSendTimeout
	}

	opts := []mail.Option{
		mail.WithPort(c.Port),
		mail.WithTimeout(c.SendTimeout),
		mail.WithTLSPolicy(mail.TLSOpportunistic),
	}

	// Only enable SMTP AUTH when credentials are supplied; some relays (and the
	// local dev MailHog/Mailpit) accept unauthenticated submission.
	if c.Username != "" || c.Password != "" {
		opts = append(
			opts,
			mail.WithSMTPAuth(mail.SMTPAuthLogin),
			mail.WithUsername(c.Username),
			mail.WithPassword(c.Password),
		)
	}

	client, err := mail.NewClient(c.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("mailer: new smtp client: %w", err)
	}

	return &SMTPMailer{cfg: c, client: client}, nil
}

// SendVerification builds and sends the verification email.
func (m *SMTPMailer) SendVerification(ctx context.Context, to, token string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.cfg.From); err != nil {
		return fmt.Errorf("mailer: set from: %w", err)
	}

	if err := msg.To(to); err != nil {
		// Do not echo the address in a way that could end up in a shared log;
		// go-mail's error already redacts. Wrap with a generic message.
		return fmt.Errorf("mailer: set recipient: %w", err)
	}

	msg.Subject("Verify your CoverOnes account")
	msg.SetBodyString(mail.TypeTextPlain, verificationBody(token))

	// Bound the send by ctx + the configured timeout so a hung SMTP server cannot
	// block the caller's goroutine indefinitely.
	sendCtx, cancel := context.WithTimeout(ctx, m.cfg.SendTimeout)
	defer cancel()

	if err := m.client.DialAndSendWithContext(sendCtx, msg); err != nil {
		return fmt.Errorf("mailer: send verification: %w", err)
	}

	return nil
}

// verificationBody renders the plaintext email body. The token is single-use and
// short-lived; it is included so the recipient can complete verification.
func verificationBody(token string) string {
	return fmt.Sprintf(
		"Welcome to CoverOnes!\n\n"+
			"Please verify your email address by submitting the token below to the\n"+
			"verify-email endpoint (POST /v1/auth/verify-email).\n\n"+
			"Verification token:\n%s\n\n"+
			"This token is single-use and expires soon. If you did not create this\n"+
			"account you can safely ignore this message.\n",
		token,
	)
}
