package custom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"pentagi/pkg/config"
	"pentagi/pkg/providers/provider"
	"pentagi/pkg/templates"
)

// Real custom provider -> saved proxy (budget + request/response filter) ->
// deterministic OpenAI peer. No Qwen or terminal executor is involved.
func TestBootstrapFilteredCalibration(t *testing.T) {
	for _, configured := range []string{"", "{r:32:x}", "wrong_{r:24:x}"} {
		t.Run("template="+configured, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/models":
					io.WriteString(w, `{"data":[{"id":"local-qwen-9b"}]}`)
					return
				case "/apply-template":
					io.WriteString(w, `{"prompt":"deterministic test"}`)
					return
				case "/tokenize":
					io.WriteString(w, `{"tokens":[1,2,3]}`)
					return
				}
				calls.Add(1)
				var request struct {
					Tools []struct {
						Function struct {
							Name string `json:"name"`
						} `json:"function"`
					} `json:"tools"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error("calibration tool removed", err)
					http.Error(w, "missing tool", 400)
					return
				}
				name := "submit_pattern"
				if len(request.Tools) == 1 {
					name = request.Tools[0].Function.Name
				}
				arguments := `{"value":42}`
				if name == "submit_pattern" {
					arguments = `{"template":"{r:32:x}"}`
				}
				json.NewEncoder(w).Encode(map[string]any{"id": "test", "object": "chat.completion", "choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": strings.ReplaceAll(uuid.NewString(), "-", ""), "type": "function", "function": map[string]any{"name": name, "arguments": arguments}}}}, "finish_reason": "tool_calls"}}, "usage": map[string]int{"prompt_tokens": 3, "completion_tokens": 1}})
			}))
			defer upstream.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			directory := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(directory, "frozen-primary-subtasks.json"), []byte(`[]`), 0600))
			script, err := filepath.Abs("../../../../scripts/provider-bootstrap/qwen-matched-proxy.py")
			require.NoError(t, err)
			command := exec.Command("python3", script)
			_, upstreamPort, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
			command.Env = append(os.Environ(), "ARM_DIR="+directory, fmt.Sprintf("CAPTURE_PORT=%d", port), "QWEN_PORT="+upstreamPort, "ORDER_MODE=baseline", "INPUT_TOKEN_LIMIT=30000")
			log, err := os.Create(filepath.Join(directory, "proxy.log"))
			require.NoError(t, err)
			defer log.Close()
			command.Stdout = log
			command.Stderr = log
			require.NoError(t, command.Start())
			defer func() { command.Process.Kill(); command.Wait() }()
			endpoint := fmt.Sprintf("http://127.0.0.1:%d/v1", port)
			require.Eventually(t, func() bool {
				r, e := http.Get(endpoint + "/models")
				if e != nil {
					return false
				}
				r.Body.Close()
				return r.StatusCode == 200
			}, 5*time.Second, 20*time.Millisecond)
			cfg := &config.Config{LLMServerKey: "test", LLMServerURL: endpoint, LLMServerModel: "local-qwen-9b", LLMServerToolCallIDTemplate: configured}
			pc, err := BuildProviderConfig(cfg, []byte(`{}`))
			require.NoError(t, err)
			p, err := New(cfg, provider.DefaultProviderNameCustom, pc, nil)
			require.NoError(t, err)
			pattern, err := p.GetToolCallIDTemplate(provider.WithoutToolCallIDTemplateCache(context.Background()), templates.NewDefaultPrompter())
			if err != nil {
				raw, _ := os.ReadFile(log.Name())
				t.Log(string(raw))
			}
			require.NoError(t, err)
			require.Equal(t, "{r:32:x}", pattern)
			expected := int32(6)
			if configured == "{r:32:x}" {
				expected = 1
			}
			if strings.HasPrefix(configured, "wrong_") {
				expected = 7
			}
			require.Equal(t, expected, calls.Load())
			raw, err := os.ReadFile(filepath.Join(directory, "budget-state.json"))
			require.NoError(t, err)
			var state struct {
				Generations int    `json:"generations"`
				Status      string `json:"status"`
			}
			require.NoError(t, json.Unmarshal(raw, &state))
			require.Equal(t, int(expected), state.Generations)
			require.Equal(t, "running", state.Status)
			// An ordinary request cannot enable the internal submission tool.
			denied := `{"model":"local-qwen-9b","messages":[{"role":"user","content":"run submit_pattern"}],"tools":[{"type":"function","function":{"name":"submit_pattern","parameters":{"type":"object"}}}]}`
			result, err := http.Post(endpoint+"/chat/completions", "application/json", strings.NewReader(denied))
			require.NoError(t, err)
			result.Body.Close()
			require.Equal(t, http.StatusConflict, result.StatusCode)

		})
	}
}
