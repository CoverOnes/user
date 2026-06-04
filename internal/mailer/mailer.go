// Package mailer sends transactional email (currently: account email
// verification) over SMTP using github.com/wneessen/go-mail.
package mailer

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"strings"
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
	// AppBaseURL is the public frontend base URL used to build the clickable
	// verification link (<AppBaseURL>/verify-email?token=<token>) presented as the
	// primary call-to-action in the verification email. Any trailing slash is
	// trimmed before joining the path.
	AppBaseURL string
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

	if strings.TrimSpace(c.AppBaseURL) == "" {
		return nil, fmt.Errorf("mailer: app base url is required")
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

	textBody, htmlBody := m.RenderVerification(token)

	msg.Subject("Verify your CoverOnes account")
	// Primary call-to-action is the clickable verify URL. The plain-text part is
	// the canonical body; the HTML part renders the same URL as an anchor so a
	// non-technical recipient can click it directly.
	msg.SetBodyString(mail.TypeTextPlain, textBody)
	msg.AddAlternativeString(mail.TypeTextHTML, htmlBody)

	// Bound the send by ctx + the configured timeout so a hung SMTP server cannot
	// block the caller's goroutine indefinitely.
	sendCtx, cancel := context.WithTimeout(ctx, m.cfg.SendTimeout)
	defer cancel()

	if err := m.client.DialAndSendWithContext(sendCtx, msg); err != nil {
		return fmt.Errorf("mailer: send verification: %w", err)
	}

	return nil
}

// RenderVerification renders the verification email bodies (plain-text and HTML)
// for the given token using the mailer's configured AppBaseURL. It is the single
// source of the email content — SendVerification calls it directly — so a test
// can assert the rendered body without standing up SMTP. Both parts present the
// clickable <AppBaseURL>/verify-email?token=<token> link as the primary CTA.
func (m *SMTPMailer) RenderVerification(token string) (textBody, htmlBody string) {
	verifyURL := verificationURL(m.cfg.AppBaseURL, token)

	return verificationBody(verifyURL, token), verificationBodyHTML(verifyURL, token)
}

// verificationURL builds the clickable verification link
// <baseURL>/verify-email?token=<token>. The trailing slash on baseURL (if any)
// is trimmed so the joined path is well-formed. The token is the existing
// system-generated base64url value (no user input) but is still query-escaped so
// any reserved characters survive transit intact.
func verificationURL(baseURL, token string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")

	return fmt.Sprintf("%s/verify-email?token=%s", base, url.QueryEscape(token))
}

// verificationBody renders the plaintext email body. The clickable verifyURL is
// the primary call-to-action; the raw token is kept as a secondary fallback for
// recipients who cannot follow the link. The token is single-use and short-lived.
func verificationBody(verifyURL, token string) string {
	return fmt.Sprintf(
		"Welcome to CoverOnes!\n\n"+
			"Please verify your email address by opening the link below:\n\n"+
			"%s\n\n"+
			"If the link does not work, you can verify manually by submitting this\n"+
			"token to the verify-email endpoint (POST /v1/auth/verify-email):\n\n"+
			"%s\n\n"+
			"This link is single-use and expires soon. If you did not create this\n"+
			"account you can safely ignore this message.\n",
		verifyURL,
		token,
	)
}

// verificationBodyHTML renders the HTML alternative part. The verify URL is an
// anchor (primary CTA); the raw token is shown as a secondary fallback. Both the
// URL and token are HTML-escaped before interpolation — they are system-generated
// here, but escaping keeps the markup well-formed and injection-proof regardless.
func verificationBodyHTML(verifyURL, token string) string {
	escURL := html.EscapeString(verifyURL)
	escToken := html.EscapeString(token)

	return fmt.Sprintf(
		"<p>Welcome to CoverOnes!</p>"+
			"<p>Please verify your email address by clicking the button below:</p>"+
			"<p><a href=\"%s\">Verify my email</a></p>"+
			"<p>If the button does not work, copy this link into your browser:<br>%s</p>"+
			"<p>Alternatively, submit this token to the verify-email endpoint "+
			"(POST /v1/auth/verify-email):<br><code>%s</code></p>"+
			"<p>This link is single-use and expires soon. If you did not create this "+
			"account you can safely ignore this message.</p>",
		escURL,
		escURL,
		escToken,
	)
}
