package ffuf

import (
        "fmt"
        "strconv"
        "strings"
        "time"
)

const Version = "2.3.0"

const DefaultWordlistURL = "https://raw.githubusercontent.com/xhackingz/apifuzz/refs/heads/master/wordlists/ultimate_fuzz_master.txt"

type Result struct {
        Input            map[string][]byte `json:"input"`
        Position         int               `json:"position"`
        StatusCode       int64             `json:"status"`
        ContentLength    int64             `json:"length"`
        ContentWords     int64             `json:"words"`
        ContentLines     int64             `json:"lines"`
        ContentType      string            `json:"content-type"`
        RedirectLocation string            `json:"redirectlocation"`
        Url              string            `json:"url"`
        Duration         time.Duration     `json:"duration"`
        Host             string            `json:"host"`
        RetryAfter       int64             `json:"-"`
}

type FilterProvider interface {
        Filter(r *Result) (bool, error)
        Repr() string
        ReprVerbose() string
}

type OutputProvider interface {
        Banner()
        PrintTableHeader()
        Finalize() error
        Result(r Result)
        PrintResult(r Result, reason string)
        Info(s string)
        Error(s string)
        Warning(s string)
        Raw(s string)
}

// ─── Inline filter entries used by auto-calibration ──────────────────────────

type SizeFilterEntry struct{ Value string }

func (f *SizeFilterEntry) Filter(r *Result) (bool, error) {
        for _, part := range strings.Split(f.Value, ",") {
                n, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
                if err != nil {
                        continue
                }
                if r.ContentLength == n {
                        return true, nil
                }
        }
        return false, nil
}
func (f *SizeFilterEntry) Repr() string        { return f.Value }
func (f *SizeFilterEntry) ReprVerbose() string { return "Response size: " + f.Value }

type WordFilterEntry struct{ Value string }

func (f *WordFilterEntry) Filter(r *Result) (bool, error) {
        for _, part := range strings.Split(f.Value, ",") {
                n, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
                if err != nil {
                        continue
                }
                if r.ContentWords == n {
                        return true, nil
                }
        }
        return false, nil
}
func (f *WordFilterEntry) Repr() string        { return f.Value }
func (f *WordFilterEntry) ReprVerbose() string { return "Response words: " + f.Value }

type LineFilterEntry struct{ Value string }

func (f *LineFilterEntry) Filter(r *Result) (bool, error) {
        for _, part := range strings.Split(f.Value, ",") {
                n, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
                if err != nil {
                        continue
                }
                if r.ContentLines == n {
                        return true, nil
                }
        }
        return false, nil
}
func (f *LineFilterEntry) Repr() string        { return f.Value }
func (f *LineFilterEntry) ReprVerbose() string { return fmt.Sprintf("Response lines: %s", f.Value) }
