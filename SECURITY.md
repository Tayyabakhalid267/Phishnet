# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please follow these steps:

1. **DO NOT** open a public issue
2. Email security details to: security@phishnet.ai (or open a private security advisory on GitHub)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 7 days
- **Fix Timeline:** Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Within 90 days

## Security Best Practices

### For Deployment

- Always use HTTPS in production
- Change default admin credentials immediately
- Use strong, random secrets for JWT and encryption keys
- Enable rate limiting
- Keep dependencies updated
- Use environment variables for secrets (never commit to git)
- Enable CORS only for trusted domains
- Implement proper authentication and authorization

### For Development

- Never commit `.env` files
- Use `.env.example` as template
- Run security scanners regularly
- Review dependencies for known vulnerabilities
- Follow OWASP security guidelines

## Known Security Considerations

- Admin panel uses localStorage for demo purposes - implement server-side sessions in production
- Default credentials are for demo only - change immediately
- AI model outputs should be validated before use in security decisions

## Updates

We will notify users of security updates through:
- GitHub Security Advisories
- Release notes
- Email (for registered users)

Thank you for helping keep PHISHNET secure! 🔒
