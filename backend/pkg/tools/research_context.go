package tools

import (
	"regexp"
	"strings"
)

var (
	researchCredentialHeading = regexp.MustCompile(`(?i)\b(?:credentials?|test\s+accounts?|login\s+details?)\b`)
	researchCredentialPair    = regexp.MustCompile(`(?i)(\b(?:[a-z0-9_.+-]+@[a-z0-9.-]+\.[a-z]{2,}|[a-z0-9_.+-]{2,})\s*(?:/|:)\s*)([^\s,;)]+)(\)?)`)
	researchCredentialLine    = regexp.MustCompile(`(?i)^\s*(?:(?:[-*]\s+)?(?:[a-z0-9_.+-]+@[a-z0-9.-]+\.[a-z]{2,}|[a-z0-9_.+-]{2,}))\s*(?:/|:)`)
	researchBareTarget        = regexp.MustCompile(`(?i)^[a-z0-9.-]+\.[a-z]{2,}(?::[0-9]+)?(?:/|$)`)
	researchURL               = regexp.MustCompile(`(?i)https?://[^\s,;)]+`)
	researchAuthHeader        = regexp.MustCompile(`(?i)(\bauthorization\s*:\s*)[^\r\n]+`)
	researchSecretAssignment  = regexp.MustCompile(`(?i)(\b[A-Za-z0-9_]*(?:password|passwd|passcode|username|user|email|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|secret|bearer)\s*(?:[:=]\s*|\s+))[^\s,;]+`)
	researchCurlUser          = regexp.MustCompile(`(?i)((?:curl\s+[^\r\n]*?\s)?(?:--user|-u)\s+['"]?[^:'"\s]+:)[^'"\s]+`)
)

// RedactCredentialsFromResearchContext removes common secrets before context is
// sent to research-only agents. It retains authorized scope and useful evidence.
func RedactCredentialsFromResearchContext(context string) string {
	context = researchAuthHeader.ReplaceAllString(context, `${1}[REDACTED]`)
	context = researchSecretAssignment.ReplaceAllString(context, `${1}[REDACTED]`)
	context = researchCurlUser.ReplaceAllString(context, `${1}[REDACTED]`)

	lines := strings.SplitAfter(context, "\n")
	inCredentialBlock := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if researchCredentialHeading.MatchString(line) {
			inCredentialBlock = true
		} else if inCredentialBlock && trimmed == "" {
			inCredentialBlock = false
		} else if inCredentialBlock && !isResearchCredentialLine(line) {
			inCredentialBlock = false
		}
		if researchCredentialHeading.MatchString(line) || (inCredentialBlock && isResearchCredentialLine(line)) {
			lines[i] = redactCredentialPairs(line)
		}
	}
	return strings.Join(lines, "")
}

func isResearchCredentialLine(line string) bool {
	value := strings.TrimSpace(line)
	value = strings.TrimLeft(value, "-* \t")
	if strings.HasPrefix(strings.ToLower(value), "https://") || strings.HasPrefix(strings.ToLower(value), "http://") {
		return false
	}
	if researchBareTarget.MatchString(value) {
		return false
	}
	if !researchCredentialLine.MatchString(line) {
		return false
	}
	account := strings.FieldsFunc(value, func(r rune) bool {
		return r == '/' || r == ':' || r == '(' || r == ' ' || r == '\t'
	})
	if len(account) == 0 {
		return false
	}
	switch strings.ToLower(account[0]) {
	case "scope", "target", "targets", "service", "services", "host", "hosts", "url", "urls", "endpoint", "endpoints", "route", "routes", "api", "docs", "documentation", "credential", "credentials", "authorization", "password", "secret", "token":
		return false
	default:
		return true
	}
}

func redactCredentialPairs(line string) string {
	if heading := researchCredentialHeading.FindStringIndex(line); heading != nil {
		if colon := strings.IndexByte(line[heading[1]:], ':'); colon >= 0 {
			valueStart := heading[1] + colon + 1
			value := line[valueStart:]
			urls := researchURL.FindAllString(value, -1)
			value = researchURL.ReplaceAllString(value, "[AUTHORIZED URL]")
			value = researchCredentialPair.ReplaceAllString(value, `[REDACTED ACCOUNT]`)
			for _, url := range urls {
				value = strings.Replace(value, "[AUTHORIZED URL]", url, 1)
			}
			return line[:valueStart] + value
		}
		return line
	}
	return researchCredentialPair.ReplaceAllString(line, `[REDACTED ACCOUNT]`)
}
