package providers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"pentagi/pkg/database"
	"pentagi/pkg/templates"
	"pentagi/pkg/tools"

	"github.com/stretchr/testify/require"
	"github.com/vxcontrol/langchaingo/llms"
)

type authenticatedContextQuerier struct {
	database.Querier
	task    database.Task
	subtask database.Subtask
}

func (q authenticatedContextQuerier) GetTask(context.Context, int64) (database.Task, error) {
	return q.task, nil
}

func (q authenticatedContextQuerier) GetSubtask(context.Context, int64) (database.Subtask, error) {
	return q.subtask, nil
}

type failingPentesterExecutor struct{ tools.FlowToolsExecutor }

func (failingPentesterExecutor) GetPentesterExecutor(tools.PentesterExecutorConfig) (tools.ContextToolsExecutor, error) {
	return nil, errors.New("test executor stops after prompt render")
}

type capturingPrompter struct {
	templates.Prompter
	question string
}

func (p *capturingPrompter) RenderTemplate(kind templates.PromptType, params any) (string, error) {
	rendered, err := p.Prompter.RenderTemplate(kind, params)
	if kind == templates.PromptTypeQuestionPentester {
		p.question = rendered
	}
	return rendered, err
}

func TestPentesterUserContextScopesOriginalTaskInputToAuthenticatedAssessmentSubtask(t *testing.T) {
	task := &database.Task{
		ID: 10, FlowID: 4, Title: "Authorized security assessment",
		Input: "Assess https://target.example. Credentials: alice@example.test / Alpha-Secret-71! and bob@example.test / Beta-Secret-82!",
	}
	authSubtask := &database.Subtask{ID: 21, TaskID: 10, Title: "Authenticated access verification", Description: "Login with each supplied account and verify access to authorized resources."}
	docsSubtask := &database.Subtask{ID: 20, TaskID: 10, Title: "Review API documentation", Description: "Find documented endpoints and methods."}
	questionWithSecret := "Review docs; password=Alpha-Secret-71!"

	auth := pentesterUserContext(task, authSubtask, "Perform authenticated checks", "scope https://target.example\npassword: Alpha-Secret-71!")
	require.Contains(t, auth["AuthorizedAssessmentContext"], "Alpha-Secret-71!")
	require.Contains(t, auth["AuthorizedAssessmentContext"], "Beta-Secret-82!")
	require.Contains(t, auth["ExecutionContext"], "[REDACTED]")

	for name, context := range map[string]map[string]any{
		"documentation-only subtask": pentesterUserContext(task, docsSubtask, questionWithSecret, "password: Alpha-Secret-71!"),
		"unrelated task":             pentesterUserContext(&database.Task{ID: 11, FlowID: 4, Title: "Write documentation", Input: "password: Alpha-Secret-71!"}, &database.Subtask{ID: 22, TaskID: 11, Title: "Document API"}, questionWithSecret, "password: Alpha-Secret-71!"),
		"foreign task relationship":  pentesterUserContext(task, &database.Subtask{ID: 23, TaskID: 12, Title: "Authenticated test"}, questionWithSecret, "password: Alpha-Secret-71!"),
	} {
		t.Run(name, func(t *testing.T) {
			require.Empty(t, context["AuthorizedAssessmentContext"])
			rendered, err := templates.NewDefaultPrompter().RenderTemplate(templates.PromptTypeQuestionPentester, context)
			require.NoError(t, err)
			require.NotContains(t, rendered, "Alpha-Secret-71!")
			require.NotContains(t, rendered, "Beta-Secret-82!")
		})
	}
}

func TestPentesterHandlerQuestionTemplateRendersPrivateAuthenticatedTaskContext(t *testing.T) {
	task := &database.Task{ID: 10, FlowID: 4, Title: "Authorized assessment", Input: "Target https://target.example; credentials alice / Alpha-Secret-71!"}
	subtask := &database.Subtask{ID: 21, TaskID: 10, Title: "Authenticated access verification", Description: "Authenticate using supplied credentials and test access."}
	context := pentesterUserContext(task, subtask, "Verify authorized access", "Target https://target.example\ncredentials alice / Alpha-Secret-71!")
	rendered, err := templates.NewDefaultPrompter().RenderTemplate(templates.PromptTypeQuestionPentester, context)
	require.NoError(t, err)
	require.Contains(t, rendered, "<authorized_assessment_context>")
	require.Contains(t, rendered, "Alpha-Secret-71!")
	require.Contains(t, rendered, "https://target.example")
	for _, oracle := range []string{"INV-1001", "INV-1002", "BOLA", "HTTP 200", "expected vulnerability"} {
		require.False(t, strings.Contains(rendered, oracle), "unexpected fixture result %q", oracle)
	}
}

func TestGetPentesterHandlerRendersAuthorizedContextForBoundSubtask(t *testing.T) {
	task := database.Task{ID: 10, FlowID: 4, Title: "Authorized security assessment", Input: "Target https://target.example. Credentials: alice / Alpha-Secret-71!"}
	subtask := database.Subtask{ID: 21, TaskID: 10, Title: "Authenticated verification", Description: "Authenticate using the supplied account and test access.", Context: "scope https://target.example"}
	query := authenticatedContextQuerier{task: task, subtask: subtask}
	prompter := &capturingPrompter{Prompter: templates.NewDefaultPrompter()}
	fp := newFlowProvider()
	fp.flowID = task.FlowID
	fp.db = query
	fp.prompter = prompter
	fp.executor = failingPentesterExecutor{}
	taskID, subtaskID := task.ID, subtask.ID
	handler, err := fp.GetPentesterHandler(t.Context(), &taskID, &subtaskID)
	require.NoError(t, err)
	args, err := json.Marshal(tools.PentesterAction{Question: "Verify account access"})
	require.NoError(t, err)
	_, err = handler(t.Context(), "pentester", args)
	require.ErrorContains(t, err, "test executor stops after prompt render")
	require.Contains(t, prompter.question, "<authorized_assessment_context>")
	require.Contains(t, prompter.question, "Alpha-Secret-71!")
	require.NotContains(t, redactPrivateAssessmentContext(prompter.question), "Alpha-Secret-71!")
}

func TestGetPentesterHandlerRejectsForeignFlowAndSubtaskBindings(t *testing.T) {
	tests := []struct {
		name    string
		task    database.Task
		subtask database.Subtask
		want    string
	}{
		{name: "foreign flow", task: database.Task{ID: 10, FlowID: 5}, subtask: database.Subtask{ID: 21, TaskID: 10}, want: "does not belong to flow"},
		{name: "foreign task", task: database.Task{ID: 10, FlowID: 4}, subtask: database.Subtask{ID: 21, TaskID: 11}, want: "does not belong to task"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := newFlowProvider()
			fp.flowID = 4
			fp.db = authenticatedContextQuerier{task: tt.task, subtask: tt.subtask}
			taskID, subtaskID := tt.task.ID, tt.subtask.ID
			_, err := fp.GetPentesterHandler(t.Context(), &taskID, &subtaskID)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestSearcherContextNeverReceivesTaskInputCredentials(t *testing.T) {
	task := &database.Task{ID: 10, FlowID: 4, Title: "assessment", Input: "credentials: alice / Alpha-Secret-71!"}
	subtask := &database.Subtask{ID: 21, TaskID: 10, Title: "docs", Description: "password: Alpha-Secret-71!"}
	question, searchTask, searchSubtask, executionContext := sanitizeSearcherContext(
		"lookup password=Alpha-Secret-71!", task, subtask, "password: Alpha-Secret-71!",
	)
	for _, value := range []string{question, searchTask.Title, searchSubtask.Title, executionContext} {
		require.NotContains(t, value, "Alpha-Secret-71!")
	}
	require.NotContains(t, searchTask.Input, "Alpha-Secret-71!")
	require.NotContains(t, searchSubtask.Description, "Alpha-Secret-71!")
}

func TestPrivateAssessmentContextIsRedactedFromStoredChainCopy(t *testing.T) {
	live := []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman,
		"<authorized_assessment_context>Credentials: alice / Alpha-Secret-71!</authorized_assessment_context>")}
	blob, err := marshalChainForStorage(live)
	require.NoError(t, err)
	require.NotContains(t, string(blob), "Alpha-Secret-71!")
	require.Contains(t, string(blob), "[REDACTED]")
	require.Contains(t, live[0].Parts[0].(llms.TextContent).Text, "Alpha-Secret-71!", "the live request must retain authorized credentials")
}
