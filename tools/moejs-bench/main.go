// Runs middleware.mjs the way Magpie does (Go moejs, a fresh runtime per request, the
// hook interrupted at its time budget) over the cases written by gen-corpus.mjs, and
// checks each result against what Node produced for the same case.
//
//	go run . <plugin-root> <corpus.ndjson> [budget-ms]
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MoeForge/moejs"
)

type testCase struct {
	Name     string          `json:"name"`
	Protocol string          `json:"protocol"`
	Body     json.RawMessage `json:"body"`
	Options  json.RawMessage `json:"options"`
	Expected json.RawMessage `json:"expected"`
}

func must[T any](x T, err error) T {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return x
}

// canonical re-encodes JSON so key order and spacing do not matter.
func canonical(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return buf.String()
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: go run . <plugin-root> <corpus.ndjson> [budget-ms]")
		os.Exit(2)
	}
	root := must(filepath.Abs(os.Args[1]))
	budget := 250 * time.Millisecond
	if len(os.Args) > 3 {
		var ms int
		fmt.Sscanf(os.Args[3], "%d", &ms)
		budget = time.Duration(ms) * time.Millisecond
	}

	modules := map[string]*moejs.Module{}
	compile := func(path string) *moejs.Module {
		if m, ok := modules[path]; ok {
			return m
		}
		m := must(moejs.Compile(path, string(must(os.ReadFile(path)))))
		modules[path] = m
		return m
	}
	// Magpie only allows relative imports inside the plugin directory.
	entry := must(moejs.Link(compile(filepath.Join(root, "middleware.mjs")), func(ref moejs.Referrer, spec string) (*moejs.Module, error) {
		if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") {
			return nil, fmt.Errorf("import %q is not relative", spec)
		}
		return compile(filepath.Join(filepath.Dir(ref.Name()), spec)), nil
	}))
	hook := must(entry.Hook("onProvider"))

	in := must(os.Open(os.Args[2]))
	defer in.Close()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1<<20), 1<<30)

	failed := 0
	fmt.Printf("%-34s %10s %10s  %s\n", "case", "bytes", "hook ms", "result")
	for scanner.Scan() {
		var c testCase
		if err := json.Unmarshal(scanner.Bytes(), &c); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		options := "{}"
		if len(c.Options) > 0 {
			options = string(c.Options)
		}

		rt := moejs.NewRuntime(moejs.Options{})
		if err := rt.Load(entry); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		body := must(rt.ParseJSONString(string(c.Body)))
		ctx := must(rt.ParseJSONString(fmt.Sprintf(`{"protocol":%q,"provider":{"id":"agy2api"},"options":%s}`, c.Protocol, options)))

		timer := time.AfterFunc(budget, func() { rt.Interrupt("hook budget exceeded") })
		start := time.Now()
		result, err := rt.Call(hook, body, ctx)
		elapsed := time.Since(start)
		timer.Stop()
		rt.ClearInterrupt()

		status := "ok"
		switch {
		case err != nil:
			status = "FAIL " + err.Error()
		case result.IsUndefined():
			if string(c.Expected) != "null" {
				status = "FAIL returned undefined, Node returned a body"
			}
		default:
			got := must(rt.AppendJSON(nil, result))
			if canonical(got) != canonical(c.Expected) {
				status = "FAIL output differs from Node"
			}
		}
		if status != "ok" {
			failed++
		}
		fmt.Printf("%-34s %10d %10.1f  %s\n", c.Name, len(c.Body), float64(elapsed.Microseconds())/1000, status)
	}
	if failed > 0 {
		fmt.Printf("\n%d case(s) failed (budget %s)\n", failed, budget)
		os.Exit(1)
	}
	fmt.Printf("\nall cases within %s and identical to Node\n", budget)
}
