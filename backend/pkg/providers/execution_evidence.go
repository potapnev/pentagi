package providers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"pentagi/pkg/database"
	"pentagi/pkg/tools"
)

var (
	commandURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)
	requestMethodFlag = regexp.MustCompile(`(?:^|\s)(?:-X|--request(?:=|\s+))\s*['"]?([A-Za-z]+)`)
	requestHeadFlag   = regexp.MustCompile(`(?:^|\s)(?:--head|-I)(?:\s|$)`)
	requestDataFlag   = regexp.MustCompile(`(?:^|\s)(?:--data(?:-[A-Za-z]+)?(?:=|\s+)|-d\s)`)
	bearerHeader      = regexp.MustCompile(`(?i)authorization\s*:\s*(?:bearer\s+)?([^\s,'"]+)`)
	httpStatusLine    = regexp.MustCompile(`(?m)^HTTP/\d(?:\.\d)?\s+([1-5][0-9]{2})(?:\s|$)`)
	secretHeaderValue = regexp.MustCompile(`(?i)((?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*(?:bearer\s+|basic\s+)?)[^\s,'"]+`)
	secretAssignment  = regexp.MustCompile(`(?i)\b((?:access[_-]?token|refresh[_-]?token|session(?:[_-]?id)?|csrf(?:[_-]?token)?|jwt|credential|api[_-]?key|password|passwd|secret)\s*[:=]\s*)[^\s&,'"]+`)
	bearerValue       = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]+=*`)
)

// associateTerminalToolcalls enriches the generic terminal message with request
// metadata from the matching persisted tool call. It redacts secrets and never
// infers HTTP status from a response body or process exit.
func associateTerminalToolcalls(msgLogs []database.Msglog, calls []database.Toolcall, taskID int64) []database.Msglog {
	result := append([]database.Msglog(nil), msgLogs...)
	matched := make([]bool, len(msgLogs))
	callerByToken := make(map[[32]byte]string)
	identityResponseByToken := make(map[[32]byte]string)

	for _, call := range calls {
		if call.Name != tools.TerminalToolName || !call.TaskID.Valid || call.TaskID.Int64 != taskID {
			continue
		}
		var action tools.TerminalAction
		if err := json.Unmarshal(call.Args, &action); err != nil {
			continue
		}
		method, requestURL, ok := terminalHTTPRequest(action.Input)
		if !ok || method != "GET" || !strings.HasSuffix(mustURLPath(requestURL), "/me") {
			continue
		}
		if token := terminalBearerToken(action.Input); token != "" && call.Status == database.ToolcallStatusFinished {
			if identity := responseIdentity(call.Result); identity != "" {
				hash := sha256.Sum256([]byte(token))
				observed := identity + " (HTTP status not captured)"
				if status := httpStatusLine.FindStringSubmatch(call.Result); len(status) == 2 {
					observed = identity + " (HTTP status " + status[1] + ")"
				}
				if prior := identityResponseByToken[hash]; prior != "" && prior != observed {
					identityResponseByToken[hash] = "ambiguous"
				} else if prior == "" {
					identityResponseByToken[hash] = observed
				}
				if prior := callerByToken[hash]; prior != "" && prior != identity {
					callerByToken[hash] = "ambiguous"
				} else if prior == "" && hasSuccessfulHTTPStatus(call.Result) {
					callerByToken[hash] = identity
				}
			}
		}
	}

	for _, call := range calls {
		if call.Name != tools.TerminalToolName || !call.TaskID.Valid || call.TaskID.Int64 != taskID {
			continue
		}

		var action tools.TerminalAction
		if err := json.Unmarshal(call.Args, &action); err != nil || action.Input == "" {
			continue
		}
		method, requestURL, ok := terminalHTTPRequest(action.Input)
		if !ok {
			continue
		}

		message := strings.TrimSpace(redactEvidenceText(action.Message))
		if message == "" {
			message = "Terminal HTTP request"
		}
		caller := "not established"
		identityResponse := ""
		if token := terminalBearerToken(action.Input); token != "" {
			hash := sha256.Sum256([]byte(token))
			if identity := callerByToken[hash]; identity != "" {
				caller = identity
			}
			identityResponse = identityResponseByToken[hash]
		}
		message += "\nTool execution status: " + string(call.Status)
		message += "\nCaller identity: " + caller
		if identityResponse != "" {
			message += "\nIdentity endpoint response: username " + identityResponse
		}
		message += "\nRequest: " + method + " " + requestURL
		if status := httpStatusLine.FindStringSubmatch(call.Result); len(status) == 2 {
			message += "\nHTTP status observed: " + status[1]
		} else {
			message += "\nHTTP status: not captured; do not infer it from the response body or command exit code"
		}

		receipt := database.Msglog{
			Type:      database.MsglogTypeTerminal,
			Message:   message,
			Result:    redactExecutionResult(call.Result),
			FlowID:    call.FlowID,
			TaskID:    call.TaskID,
			SubtaskID: call.SubtaskID,
			CreatedAt: call.CreatedAt,
		}
		replaced := false
		for i := range msgLogs {
			if matched[i] || msgLogs[i].Type != database.MsglogTypeTerminal ||
				msgLogs[i].Message != action.Message || msgLogs[i].Result != call.Result ||
				!sameNullableID(msgLogs[i].TaskID, call.TaskID) ||
				!sameNullableID(msgLogs[i].SubtaskID, call.SubtaskID) {
				continue
			}
			matched[i] = true
			receipt.ID = msgLogs[i].ID
			receipt.CreatedAt = msgLogs[i].CreatedAt
			result[i] = receipt
			replaced = true
			break
		}
		if !replaced {
			result = append(result, receipt)
		}
	}
	for i := range result {
		if result[i].Type == database.MsglogTypeTerminal {
			result[i].Message = redactEvidenceText(result[i].Message)
			result[i].Result = redactExecutionResult(result[i].Result)
		}
	}

	sort.SliceStable(result, func(i, j int) bool {
		if !result[i].CreatedAt.Valid || !result[j].CreatedAt.Valid {
			return false
		}
		return result[i].CreatedAt.Time.Before(result[j].CreatedAt.Time)
	})
	return result
}

func hasSuccessfulHTTPStatus(result string) bool {
	status := httpStatusLine.FindStringSubmatch(result)
	if len(status) != 2 {
		return false
	}
	code, err := strconv.Atoi(status[1])
	return err == nil && code >= 200 && code < 300
}

func terminalHTTPRequest(command string) (string, string, bool) {
	trimmed := strings.TrimSpace(command)
	// PentAGI's terminal wrapper appends this fixed descriptor merge so stderr
	// joins the captured stdout result. It does not add another request.
	trimmed = strings.TrimSuffix(trimmed, " 2>&1")
	if !strings.HasPrefix(trimmed, "curl ") || strings.ContainsAny(trimmed, "\n\r|;&`$<>\\") ||
		regexp.MustCompile(`(?:^|\s)(?:-L|--location|--config|-K)(?:\s|=|$)`).MatchString(trimmed) {
		return "", "", false
	}
	urls := commandURLPattern.FindAllString(trimmed, -1)
	if len(urls) != 1 {
		return "", "", false
	}
	urlText := urls[0]
	urlText = strings.TrimRight(urlText, ".,);]")
	u, err := url.Parse(urlText)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", false
	}
	u.User = nil
	query := u.Query()
	for key := range query {
		if isSensitiveEvidenceKey(key) {
			query.Set(key, "[REDACTED]")
		}
	}
	u.RawQuery = query.Encode()
	u.Fragment = ""

	method := "GET"
	if match := requestMethodFlag.FindStringSubmatch(command); len(match) == 2 {
		method = strings.ToUpper(match[1])
	} else if requestHeadFlag.MatchString(command) {
		method = "HEAD"
	} else if requestDataFlag.MatchString(command) {
		method = "POST"
	}
	return method, u.String(), true
}

func terminalBearerToken(command string) string {
	match := bearerHeader.FindStringSubmatch(command)
	if len(match) == 2 {
		return strings.TrimRight(match[1], "'\"`)")
	}
	return ""
}

func mustURLPath(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return u.Path
}

func responseIdentity(result string) string {
	_, body, _ := splitExecutionOutput(result)
	var value any
	if json.Unmarshal([]byte(body), &value) != nil {
		return ""
	}
	return findResponseIdentity(value)
}

func findResponseIdentity(value any) string {
	fields, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range []string{"username", "user_name", "login"} {
		if identity, ok := fields[key].(string); ok && strings.TrimSpace(identity) != "" {
			return strings.TrimSpace(identity)
		}
	}
	return ""
}

func redactExecutionResult(result string) string {
	result = redactEvidenceText(result)
	prefix, body, tail := splitExecutionOutput(result)
	if body == "" {
		return result
	}
	var value any
	if json.Unmarshal([]byte(body), &value) != nil {
		return result
	}
	redactSensitiveFields(value)
	redacted, err := json.Marshal(value)
	if err != nil {
		return result
	}
	return prefix + string(redacted) + tail
}

func splitExecutionOutput(value string) (prefix, body, tail string) {
	if index := strings.Index(value, "\n[exit code:"); index >= 0 {
		tail = value[index:]
		value = value[:index]
	}
	if index := strings.Index(value, "\r\n\r\n"); index >= 0 {
		return value[:index+4], value[index+4:], tail
	}
	if index := strings.Index(value, "\n\n"); index >= 0 {
		return value[:index+2], value[index+2:], tail
	}
	return "", value, tail
}

func redactSensitiveFields(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isSensitiveEvidenceKey(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			redactSensitiveFields(child)
		}
	case []any:
		for _, child := range typed {
			redactSensitiveFields(child)
		}
	}
}

func isSensitiveEvidenceKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
	switch normalized {
	case "token", "accesstoken", "refreshtoken", "password", "passwd", "secret", "apikey",
		"authorization", "proxyauthorization", "cookie", "setcookie", "session", "sessionid",
		"csrf", "csrftoken", "jwt", "credential", "credentials":
		return true
	default:
		return false
	}
}

func redactEvidenceText(value string) string {
	value = secretHeaderValue.ReplaceAllString(value, "$1[REDACTED]")
	value = bearerValue.ReplaceAllString(value, "${1}[REDACTED]")
	return secretAssignment.ReplaceAllString(value, "$1[REDACTED]")
}

func sameNullableID(left, right sql.NullInt64) bool {
	return left.Valid == right.Valid && (!left.Valid || left.Int64 == right.Int64)
}
