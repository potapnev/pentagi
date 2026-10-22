package providers

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pentagi/pkg/config"
	"pentagi/pkg/database"
	"pentagi/pkg/docker"
	"pentagi/pkg/tools"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
)

const (
	apiDiscoveryA3Worker = "recovery_v5e_guarded_a3-pentagi-terminal-6"
	apiDiscoveryA3Root   = "http://pentagi-effectiveness-target:8000"
)

// These live adapters capture calls through PentAGI's normal tool-call and
// terminal log provider interfaces. The test serializes those records to a
// private artifact; the controller's database writer is replaced so this runs
// without Qwen or a controller/database.
type apiDiscoveryLiveDB struct {
	database.Querier
	container database.Container
}

func (db *apiDiscoveryLiveDB) GetFlowPrimaryContainer(context.Context, int64) (database.Container, error) {
	return db.container, nil
}

type apiDiscoveryDocker struct {
	docker.DockerClient
	client *client.Client
}

func (d *apiDiscoveryDocker) IsContainerRunning(ctx context.Context, id string) (bool, error) {
	result, err := d.client.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return false, err
	}
	return result.Container.State != nil && result.Container.State.Running, nil
}

func (d *apiDiscoveryDocker) ContainerExecCreate(ctx context.Context, container string, cfg client.ExecCreateOptions) (client.ExecCreateResult, error) {
	return d.client.ExecCreate(ctx, container, cfg)
}

func (d *apiDiscoveryDocker) ContainerExecAttach(ctx context.Context, id string, cfg client.ExecAttachOptions) (client.HijackedResponse, error) {
	result, err := d.client.ExecAttach(ctx, id, cfg)
	return result.HijackedResponse, err
}

func (d *apiDiscoveryDocker) ContainerExecInspect(ctx context.Context, id string) (client.ExecInspectResult, error) {
	return d.client.ExecInspect(ctx, id, client.ExecInspectOptions{})
}

type apiDiscoveryLiveCall struct {
	ID     int64           `json:"id"`
	CallID string          `json:"call_id"`
	Name   string          `json:"name"`
	Args   json.RawMessage `json:"args"`
	Result string          `json:"result,omitempty"`
	Failed string          `json:"failed,omitempty"`
}

type apiDiscoveryLiveCalls struct {
	Calls []*apiDiscoveryLiveCall
}

func (l *apiDiscoveryLiveCalls) PutLog(_ context.Context, callID, name string, args json.RawMessage, _, _ *int64) (int64, error) {
	id := int64(len(l.Calls) + 1)
	l.Calls = append(l.Calls, &apiDiscoveryLiveCall{ID: id, CallID: callID, Name: name, Args: append(json.RawMessage(nil), args...)})
	return id, nil
}

func (l *apiDiscoveryLiveCalls) UpdateLogSuccess(_ context.Context, id int64, result string, _ float64) error {
	l.Calls[id-1].Result = result
	return nil
}

func (l *apiDiscoveryLiveCalls) UpdateLogFailed(_ context.Context, id int64, result string, _ float64) error {
	l.Calls[id-1].Failed = result
	return nil
}

type apiDiscoveryLiveTerm struct {
	Type    database.TermlogType `json:"type"`
	Message string               `json:"message"`
}

type apiDiscoveryLiveTerms struct {
	Entries []apiDiscoveryLiveTerm
}

func (l *apiDiscoveryLiveTerms) PutMsg(_ context.Context, typ database.TermlogType, msg string, _ int64, _, _ *int64) (int64, error) {
	l.Entries = append(l.Entries, apiDiscoveryLiveTerm{Type: typ, Message: msg})
	return int64(len(l.Entries)), nil
}

func (*apiDiscoveryLiveTerms) ContainerNotRunning(context.Context, int64, *int64, *int64) error {
	return nil
}
func (*apiDiscoveryLiveTerms) ContainerRunning(context.Context, int64, *int64, *int64) error {
	return nil
}

type apiDiscoveryLiveMessages struct {
	nextID int64
	values map[int64]string
}

func (l *apiDiscoveryLiveMessages) PutMsg(_ context.Context, _ database.MsglogType, _, _ *int64, _ int64, _, msg string) (int64, error) {
	l.nextID++
	if l.values == nil {
		l.values = make(map[int64]string)
	}
	l.values[l.nextID] = msg
	return l.nextID, nil
}

func (*apiDiscoveryLiveMessages) UpdateMsgResult(context.Context, int64, int64, string, database.MsglogResultFormat) error {
	return nil
}

func TestDiscoverAPIDocumentationThroughPentesterExecutor(t *testing.T) {
	if os.Getenv("PENTAGI_API_DISCOVERY_LIVE_TEST") != "1" {
		t.Skip("requires the existing authorized A3 fixture and running A3 terminal container")
	}

	ctx := t.Context()
	worker := apiDiscoveryA3Worker
	cli, err := client.New(client.FromEnv)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cli.Close() })

	apiDocker := &apiDiscoveryDocker{client: cli}
	db := &apiDiscoveryLiveDB{container: database.Container{
		ID: 6, Status: database.ContainerStatusRunning,
		LocalID: sql.NullString{String: worker, Valid: true},
	}}
	cfg := &config.Config{DataDir: t.TempDir(), TenantID: "recovery_v5e_guarded_a3", TerminalToolTimeout: 20}
	executor, err := tools.NewFlowToolsExecutor(db, cfg, apiDocker, nil, 1, 6)
	require.NoError(t, err)

	calls := &apiDiscoveryLiveCalls{}
	terms := &apiDiscoveryLiveTerms{}
	messages := &apiDiscoveryLiveMessages{}
	executor.SetToolCallLogProvider(calls)
	executor.SetTermLogProvider(terms)
	executor.SetMsgLogProvider(messages)
	taskID, subtaskID := int64(99991), int64(99992)
	unused := func(context.Context, string, json.RawMessage) (string, error) { return "unused", nil }
	pentester, err := executor.GetPentesterExecutor(tools.PentesterExecutorConfig{
		TaskID: &taskID, SubtaskID: &subtaskID,
		Adviser: unused, Coder: unused, Installer: unused,
		Memorist: unused, Searcher: unused, HackResult: unused,
	})
	require.NoError(t, err)

	// This mirrors the captured A3 Primary delegation: target scope is present
	// in the delegated question, and no credential or evaluator result is sent.
	delegatedQuestion := "Perform reconnaissance on " + apiDiscoveryA3Root + " to discover documented API routes."
	planningQuestion, pentesterPrompt := preparePentesterAPIDiscoveryContext(ctx, pentester, delegatedQuestion, "Use the existing authorized scope.")
	if !strings.Contains(planningQuestion, "HTTP 200") {
		for _, call := range calls.Calls {
			result := call.Result
			if len(result) > 700 {
				result = result[:700]
			}
			t.Logf("terminal call %s result: %q", call.CallID, result)
		}
	}
	require.Contains(t, planningQuestion, "HTTP 200")
	require.Contains(t, planningQuestion, "Documented operations:")
	require.Contains(t, pentesterPrompt, "Documented operations:")
	require.Contains(t, pentesterPrompt, "GET ")
	require.NotEmpty(t, calls.Calls)
	require.NotEmpty(t, terms.Entries)

	for _, call := range calls.Calls {
		require.Equal(t, tools.TerminalToolName, call.Name)
		require.Empty(t, call.Failed)
		require.Contains(t, call.Result, "HTTP/1.1 200")
		var args tools.TerminalAction
		require.NoError(t, json.Unmarshal(call.Args, &args))
		require.True(t, strings.HasPrefix(args.Input, "curl -sS -i "))
		require.Contains(t, args.Input, apiDiscoveryA3Root)
		require.NotContains(t, strings.ToLower(args.Input), "password")
		require.NotContains(t, strings.ToLower(args.Input), "authorization")
	}

	var artifactPath string
	if artifactPath = os.Getenv("PENTAGI_API_DISCOVERY_EVIDENCE"); artifactPath != "" {
		artifact := struct {
			Worker           string                  `json:"worker"`
			Target           string                  `json:"target"`
			PlanningContext  string                  `json:"planning_context"`
			PentesterContext string                  `json:"pentester_context"`
			ToolCalls        []*apiDiscoveryLiveCall `json:"tool_calls"`
			TerminalEntries  []apiDiscoveryLiveTerm  `json:"terminal_entries"`
		}{worker, apiDiscoveryA3Root, planningQuestion, pentesterPrompt, calls.Calls, terms.Entries}
		data, err := json.MarshalIndent(artifact, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Dir(artifactPath), 0700))
		require.NoError(t, os.WriteFile(artifactPath, data, 0600))
	}
	t.Logf("recorded %d real terminal tool calls and %d terminal log entries; routes delivered to planner and Pentester", len(calls.Calls), len(terms.Entries))
}

var _ tools.TermLogProvider = (*apiDiscoveryLiveTerms)(nil)
var _ tools.ToolCallLogProvider = (*apiDiscoveryLiveCalls)(nil)
var _ tools.MsgLogProvider = (*apiDiscoveryLiveMessages)(nil)
var _ docker.DockerClient = (*apiDiscoveryDocker)(nil)
