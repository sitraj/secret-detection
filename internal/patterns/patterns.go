package patterns

import (
	"regexp"
)

type PatternLoader struct {
	patterns map[string][]*regexp.Regexp
}

func NewPatternLoader() *PatternLoader {
	loader := &PatternLoader{
		patterns: make(map[string][]*regexp.Regexp),
	}
	loader.loadPatterns()
	return loader
}

func (p *PatternLoader) loadPatterns() {
	// API Keys
	p.addPattern("api_key", `(?i)(?:api[_-]?key|apikey)[\s:=]+['"]?([a-zA-Z0-9]{32,})['"]?`)
	
	// AWS
	p.addPattern("aws_access_key", `(?i)aws[_-]?access[_-]?key[_-]?id[\s:=]+['"]?(AKIA[0-9A-Z]{16})['"]?`)
	p.addPattern("aws_secret_key", `(?i)aws[_-]?secret[_-]?access[_-]?key[\s:=]+['"]?([a-zA-Z0-9/+]{40})['"]?`)
	
	// GitHub
	p.addPattern("github_token", `(?i)github[_-]?token[\s:=]+['"]?(ghp_[a-zA-Z0-9]{36})['"]?`)
	
	// SSH Keys
	p.addPattern("ssh_private_key", `-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`)
	
	// Database Credentials
	p.addPattern("database_url", `(?i)(?:postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+/[^?\s]+`)
	
	// OAuth Tokens
	p.addPattern("oauth_token", `(?i)oauth[_-]?token[\s:=]+['"]?([a-zA-Z0-9]{32,})['"]?`)
	
	// Slack Tokens
	p.addPattern("slack_token", `(?i)xox[baprs]-([0-9a-zA-Z]{10,48})`)
	
	// Stripe Keys
	p.addPattern("stripe_key", `(?i)stripe[_-]?key[\s:=]+['"]?(sk_[a-zA-Z0-9]{24})['"]?`)
	
	// Generic Secrets
	p.addPattern("generic_secret", `(?i)(?:secret|password|token)[\s:=]+['"]?([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,})['"]?`)
}

func (p *PatternLoader) addPattern(secretType string, pattern string) {
	regex := regexp.MustCompile(pattern)
	if _, exists := p.patterns[secretType]; !exists {
		p.patterns[secretType] = make([]*regexp.Regexp, 0)
	}
	p.patterns[secretType] = append(p.patterns[secretType], regex)
}

func (p *PatternLoader) GetPatterns() map[string][]*regexp.Regexp {
	return p.patterns
} 