package providers

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"pentagi/pkg/database"
	"pentagi/pkg/templates"
	"pentagi/pkg/tools"

	"github.com/stretchr/testify/require"
)

type executionEvidenceQuerier struct {
	database.Querier
	logs  []database.Msglog
	calls []database.Toolcall
}

func (q executionEvidenceQuerier) GetTaskMsgLogs(context.Context, sql.NullInt64) ([]database.Msglog, error) {
	return q.logs, nil
}

func (q executionEvidenceQuerier) GetFlowToolcalls(context.Context, int64) ([]database.Toolcall, error) {
	return q.calls, nil
}

func TestTerminalExecutionEvidenceKeepsRequestResponseAssociation(t *testing.T) {
	const taskID = int64(7)
	makeCall := func(id, note, command, result string, callTaskID int64) database.Toolcall {
		args, err := json.Marshal(tools.TerminalAction{
			Message: note,
			Input:   command,
		})
		require.NoError(t, err)
		return database.Toolcall{
			CallID: id, Status: database.ToolcallStatusFinished, Name: tools.TerminalToolName, Args: args, Result: result,
			TaskID: sql.NullInt64{Int64: callTaskID, Valid: true},
		}
	}

	logs := []database.Msglog{
		{Type: database.MsglogTypeTerminal, TaskID: sql.NullInt64{Int64: taskID, Valid: true}, Message: "Authenticate Alice", Result: `{"access_token":"alice-secret"}`},
		{Type: database.MsglogTypeTerminal, TaskID: sql.NullInt64{Int64: taskID, Valid: true}, Message: "Authenticate Bob", Result: `{"access_token":"bob-secret"}`},
		{Type: database.MsglogTypeTerminal, TaskID: sql.NullInt64{Int64: taskID, Valid: true}, Message: "Alice identity check", Result: "HTTP/1.1 200 OK\n\n{\"username\":\"Alice\"}"},
		{Type: database.MsglogTypeTerminal, TaskID: sql.NullInt64{Int64: taskID, Valid: true}, Message: "Bob identity check", Result: `{"username":"Bob"}`},
		{Type: database.MsglogTypeTerminal, TaskID: sql.NullInt64{Int64: taskID, Valid: true}, Message: "Alice invoice check", Result: `{"owner":"Bob"}`},
		{Type: database.MsglogTypeTerminal, TaskID: sql.NullInt64{Int64: taskID, Valid: true}, Message: "Bob invoice check", Result: `{"owner":"Alice"}`},
		{Type: database.MsglogTypeTerminal, TaskID: sql.NullInt64{Int64: taskID, Valid: true}, Message: "Bob cross-account denied control", Result: "HTTP/1.1 403 Forbidden\n{\"error\":\"forbidden\"}"},
		{Type: database.MsglogTypeTerminal, TaskID: sql.NullInt64{Int64: taskID, Valid: true}, Message: "Compound command", Result: `{"owner":"unknown"}`},
		{Type: database.MsglogTypeTerminal, TaskID: sql.NullInt64{Int64: taskID, Valid: true}, Message: "Nested identity command", Result: `{"owner":"unknown"}`},
	}
	calls := []database.Toolcall{
		makeCall("login-a", "Authenticate Alice", `curl -s -X POST https://fixture.invalid/api/session -d '{"username":"Alice","password":"super-secret"}'`, `{"access_token":"alice-secret"}`, taskID),
		makeCall("login-b", "Authenticate Bob", `curl -s -X POST https://fixture.invalid/api/session -d '{"username":"Bob","password":"super-secret"}'`, `{"access_token":"bob-secret"}`, taskID),
		makeCall("me-a", "Alice identity check", `curl -i https://fixture.invalid/api/me -H 'Authorization: Bearer alice-secret'`, "HTTP/1.1 200 OK\n\n{\"username\":\"Alice\"}", taskID),
		makeCall("me-b", "Bob identity check", `curl -s https://fixture.invalid/api/me -H 'Authorization: Bearer bob-secret'`, `{"username":"Bob"}`, taskID),
		makeCall("a", "Alice invoice check", `curl -s -H 'Authorization: Bearer alice-secret' -X GET https://fixture.invalid/api/invoices/one`, `{"owner":"Bob"}`, taskID),
		makeCall("b", "Bob invoice check", `curl -s -H 'Authorization: Bearer bob-secret' -X GET https://fixture.invalid/api/invoices/two`, `{"owner":"Alice"}`, taskID),
		makeCall("negative", "Bob cross-account denied control", `curl -i -H 'Authorization: Bearer bob-secret' https://fixture.invalid/api/invoices/three`, "HTTP/1.1 403 Forbidden\n{\"error\":\"forbidden\"}", taskID),
		makeCall("compound", "Compound command", `curl -s https://fixture.invalid/one && curl -s https://fixture.invalid/two`, `{"owner":"unknown"}`, taskID),
		makeCall("nested-me", "Nested identity", `curl -s https://fixture.invalid/api/me -H 'Authorization: Bearer nested-secret'`, `{"profile":{"name":"Unrelated Name"}}`, taskID),
		makeCall("nested-identity", "Nested identity command", `curl -s https://fixture.invalid/api/invoices/four -H 'Authorization: Bearer nested-secret'`, `{"owner":"unknown"}`, taskID),
		makeCall("other-task", "unrelated", `curl https://fixture.invalid/other`, "irrelevant", taskID+1),
	}

	fp := newFlowProvider()
	fp.flowID = 1
	fp.db = executionEvidenceQuerier{logs: logs, calls: calls}
	fp.prompter = templates.NewDefaultPrompter()
	var summaryInput string
	_, err := fp.getTaskMsgLogsSummary(t.Context(), taskID, func(_ context.Context, input string) (string, error) {
		summaryInput = input
		return "summary", nil
	})
	require.NoError(t, err)
	require.Contains(t, summaryInput, "Caller identity: Alice\nIdentity endpoint response: username Alice (HTTP status 200)\nRequest: GET https://fixture.invalid/api/invoices/one")
	require.Contains(t, summaryInput, "Caller identity: not established\nIdentity endpoint response: username Bob (HTTP status not captured)\nRequest: GET https://fixture.invalid/api/invoices/two")
	require.Contains(t, summaryInput, "HTTP status: not captured; do not infer it from the response body or command exit code")
	require.Contains(t, summaryInput, "HTTP status observed: 403")
	require.Contains(t, summaryInput, "Tool execution status: finished")
	require.Contains(t, summaryInput, "Caller identity: not established\nIdentity endpoint response: username Bob (HTTP status not captured)\nRequest: GET https://fixture.invalid/api/invoices/three\nHTTP status observed: 403")
	require.Contains(t, summaryInput, `{"owner":"Bob"}`)
	require.Contains(t, summaryInput, `{"owner":"Alice"}`)
	require.Contains(t, summaryInput, `{"error":"forbidden"}`)
	require.Contains(t, summaryInput, "Compound command")
	require.NotContains(t, summaryInput, "Request: GET https://fixture.invalid/one")
	require.Contains(t, summaryInput, "Caller identity: not established\nRequest: GET https://fixture.invalid/api/invoices/four")
	require.NotContains(t, strings.ToLower(summaryInput), "vulnerable")
	require.NotContains(t, summaryInput, "alice-secret")
	require.NotContains(t, summaryInput, "bob-secret")
	require.NotContains(t, summaryInput, "super-secret")
	require.NotContains(t, summaryInput, "nested-secret")
}
