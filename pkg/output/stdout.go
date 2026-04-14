package output

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"apifuzz/pkg/ffuf"
)

const (
	BANNER_HEADER = `
  __  __ _               _    _             _____
 \ \/ /| |__   __ _  ___| | _(_)_ __   __ _|__  /
  \  / | '_ \ / _' |/ __| |/ / | '_ \ / _' | / /
  /  \ | | | | (_| | (__|   <| | | | | (_| |/ /_
 /_/\_\|_| |_|\__,_|\___|_|\_\_|_| |_|\__, /____|
                                       |___/
`
	BANNER_SEP    = "________________________________________________"
	BANNER_FOOTER = `
------------------------------------------------
 Author  : xhacking_z
 Twitter : x.com/xhacking_z
------------------------------------------------`
)

// ANSI color codes — always available, used selectively.
const (
	ANSI_CLEAR   = "\033[0m"
	ANSI_RED     = "\033[31m"
	ANSI_GREEN   = "\033[32m"
	ANSI_YELLOW  = "\033[33m"
	ANSI_BLUE    = "\033[34m"
	ANSI_MAGENTA = "\033[35m"
	ANSI_CYAN    = "\033[36m"
	ANSI_WHITE   = "\033[37m"
	ANSI_BOLD    = "\033[1m"
	ANSI_DIM     = "\033[2m"

	// Bright variants
	ANSI_BRIGHT_RED   = "\033[91m"
	ANSI_BRIGHT_GREEN = "\033[92m"
	ANSI_BRIGHT_CYAN  = "\033[96m"
)

type Stdoutput struct {
	conf       *ffuf.Config
	Results    []ffuf.Result
	mu         sync.Mutex
	startTime  time.Time
	catchAll   map[string]int64
	suppressed int64
	spinIndex  int
	lastDone   int64
	lastTotal  int64
	lastHits   int64
	lastErrors int64
	lastRPS    float64
}

func NewStdoutput(conf *ffuf.Config) *Stdoutput {
	return &Stdoutput{
		conf:      conf,
		Results:   make([]ffuf.Result, 0),
		startTime: time.Now(),
		catchAll:  make(map[string]int64),
	}
}

func (s *Stdoutput) Banner() {
	version := ffuf.Version
	if s.conf.Colors {
		version = ANSI_BRIGHT_CYAN + ANSI_BOLD + version + ANSI_CLEAR
		fmt.Fprintf(os.Stderr, "%s%s%s\n       v%s\n%s\n\n",
			ANSI_BRIGHT_CYAN, BANNER_HEADER, ANSI_CLEAR, version, BANNER_SEP)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n       v%s\n%s\n\n", BANNER_HEADER, version, BANNER_SEP)
	}

	printOption(s.conf.Colors, "Method", s.conf.Method)

	// Single-target vs multi-target display
	if len(s.conf.Targets) > 0 {
		printOption(s.conf.Colors, "Mode", "Multi-target")
		printOption(s.conf.Colors, "Targets", fmt.Sprintf("%d domains (FUZZ appended where missing)", len(s.conf.Targets)))
	} else {
		printOption(s.conf.Colors, "URL", s.conf.Url)
	}

	for _, wl := range s.conf.Wordlists {
		printOption(s.conf.Colors, "Wordlist", wl)
	}

	if len(s.conf.Headers) > 0 {
		for k, v := range s.conf.Headers {
			printOption(s.conf.Colors, "Header", fmt.Sprintf("%s: %s", k, v))
		}
	}

	if s.conf.Data != "" {
		printOption(s.conf.Colors, "Data", s.conf.Data)
	}

	if len(s.conf.Extensions) > 0 {
		printOption(s.conf.Colors, "Extensions", strings.Join(s.conf.Extensions, " "))
	}

	if s.conf.OutputFile != "" {
		printOption(s.conf.Colors, "Output file", s.conf.OutputFile)
		printOption(s.conf.Colors, "File format", s.conf.OutputFormat)
	}

	printOption(s.conf.Colors, "Follow redirects", fmt.Sprintf("%t", s.conf.FollowRedirects))
	printOption(s.conf.Colors, "Calibration", fmt.Sprintf("%t", s.conf.AutoCalibration))

	if s.conf.ProxyURL != "" {
		printOption(s.conf.Colors, "Proxy", s.conf.ProxyURL)
	}
	if s.conf.ReplayProxyURL != "" {
		printOption(s.conf.Colors, "ReplayProxy", s.conf.ReplayProxyURL)
	}

	printOption(s.conf.Colors, "Timeout", fmt.Sprintf("%d", s.conf.Timeout))
	printOption(s.conf.Colors, "Threads", fmt.Sprintf("%d", s.conf.Threads))

	if s.conf.Delay != "" {
		printOption(s.conf.Colors, "Delay", s.conf.Delay+" sec")
	}

	matcherKeys := sortedKeys(s.conf.Matchers)
	for _, k := range matcherKeys {
		printOption(s.conf.Colors, "Matcher", s.conf.Matchers[k].ReprVerbose())
	}

	filterKeys := sortedKeys(s.conf.Filters)
	for _, k := range filterKeys {
		printOption(s.conf.Colors, "Filter", s.conf.Filters[k].ReprVerbose())
	}

	fmt.Fprintf(os.Stderr, "%s\n\n", BANNER_SEP)
}

// PrintTableHeader prints the results column header and separator line.
// Called by the runner after all setup INFO messages so they appear above the table, not inside it.
func (s *Stdoutput) PrintTableHeader() {
	header := fmt.Sprintf("%-60s %7s %9s %7s %7s %9s", "URL", "Status", "Size", "Words", "Lines", "Duration")
	if s.conf.Colors {
		header = ANSI_BOLD + ANSI_WHITE + header + ANSI_CLEAR
	}
	fmt.Fprintln(os.Stderr, header)
	sep := strings.Repeat("-", 105)
	if s.conf.Colors {
		sep = ANSI_DIM + sep + ANSI_CLEAR
	}
	fmt.Fprintln(os.Stderr, sep)
}

func (s *Stdoutput) Result(r ffuf.Result) {
	s.mu.Lock()
	s.Results = append(s.Results, r)
	s.mu.Unlock()
	if s.conf.OutputMode == "normal" {
		s.printLine(r, "", false)
	}
}

func (s *Stdoutput) PrintResult(r ffuf.Result, reason string) {
	if s.conf.OutputMode != "normal" {
		return
	}
	s.printLine(r, reason, true)
}

func (s *Stdoutput) CatchAll(r ffuf.Result, seen int64) {
	host := hostForResult(r)
	key := fmt.Sprintf("%s|%d", host, r.ContentLength)

	s.mu.Lock()
	if seen > s.catchAll[key] {
		s.catchAll[key] = seen
	}
	s.suppressed++
	shouldPrint := s.conf.OutputMode == "normal" && !s.conf.Quiet && shouldPrintCatchAll(seen)
	s.mu.Unlock()

	if !shouldPrint {
		return
	}

	size := formatBytes(r.ContentLength)
	line := fmt.Sprintf("[CATCH-ALL] %s (%s, seen %dx)", host, size, seen)
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\r\033[2K%s\n", line)
}

func (s *Stdoutput) Progress(done, total, hits, errors int64, rps float64) {
	if s.conf.OutputMode != "live" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastDone = done
	s.lastTotal = total
	s.lastHits = hits
	s.lastErrors = errors
	s.lastRPS = rps

	spinner := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	frame := spinner[s.spinIndex%len(spinner)]
	s.spinIndex++
	fmt.Fprintf(os.Stderr, "\r\033[2K%c fuzzing... | req/s: %.0f | hits: %d | catch-all: %d | seen suppressed: %d | errors: %d | %d/%d",
		frame, rps, hits, len(s.catchAll), s.suppressed, errors, done, total)
}

func (s *Stdoutput) printLine(r ffuf.Result, reason string, dimmed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Always display the full resolved URL — never truncate.
	fullURL := r.Url

	statusStr := fmt.Sprintf("%d", r.StatusCode)

	// Pick status color: green = 2xx, cyan = 3xx, yellow = 4xx, red = 5xx
	statusColor := ANSI_BRIGHT_GREEN
	switch {
	case r.StatusCode >= 500:
		statusColor = ANSI_BRIGHT_RED
	case r.StatusCode >= 400:
		statusColor = ANSI_YELLOW
	case r.StatusCode >= 300:
		statusColor = ANSI_CYAN
	}

	durationStr := fmt.Sprintf("%dms", r.Duration.Milliseconds())

	// Build the stats portion (always same format)
	buildStats := func(colored bool) string {
		if colored && !dimmed {
			return fmt.Sprintf("%s%7s%s %9d %7d %7d %9s",
				statusColor, statusStr, ANSI_CLEAR,
				r.ContentLength, r.ContentWords, r.ContentLines, durationStr)
		}
		return fmt.Sprintf("%7s %9d %7d %7d %9s",
			statusStr, r.ContentLength, r.ContentWords, r.ContentLines, durationStr)
	}

	var line string
	coloredURL := fullURL
	if s.conf.Colors && !dimmed {
		// Color the URL itself: green for 2xx, yellow for 4xx, red for 5xx
		coloredURL = statusColor + ANSI_BOLD + fullURL + ANSI_CLEAR
	}

	if dimmed {
		stats := buildStats(false)
		line = fmt.Sprintf("%s%-60s %s [%s]%s", ANSI_DIM, fullURL, stats, reason, ANSI_CLEAR)
	} else if len(fullURL) > 60 {
		// URL too long for one line — print URL then stats indented below
		if s.conf.Colors {
			line = fmt.Sprintf("%s\n  %s", coloredURL, buildStats(true))
		} else {
			line = fmt.Sprintf("%s\n  %s", fullURL, buildStats(false))
		}
	} else {
		if s.conf.Colors {
			line = fmt.Sprintf("%-60s %s", coloredURL, buildStats(true))
		} else {
			line = fmt.Sprintf("%-60s %s", fullURL, buildStats(false))
		}
	}

	if s.conf.Verbose && r.RedirectLocation != "" {
		if s.conf.Colors {
			line += fmt.Sprintf("  %s→ %s%s", ANSI_CYAN, r.RedirectLocation, ANSI_CLEAR)
		} else {
			line += fmt.Sprintf("  -> %s", r.RedirectLocation)
		}
	}

	// Clear the progress line then print the result
	fmt.Fprintf(os.Stderr, "\r\033[2K")
	fmt.Fprintln(os.Stdout, line)
}

func (s *Stdoutput) Finalize() error {
	elapsed := time.Since(s.startTime)
	rps := 0.0
	if elapsed.Seconds() > 0 {
		rps = float64(len(s.Results)) / elapsed.Seconds()
	}

	if s.conf.OutputFile != "" {
		if err := s.writeOutput(); err != nil {
			return err
		}
	}

	if s.conf.OutputMode == "live" {
		hits := s.lastHits
		if hits == 0 {
			hits = int64(len(s.Results))
		}
		reqRate := s.lastRPS
		if reqRate == 0 {
			reqRate = rps
		}
		progress := ""
		if s.lastTotal > 0 {
			progress = fmt.Sprintf(" | %d/%d", s.lastDone, s.lastTotal)
		}
		fmt.Fprintf(os.Stderr, "\r\033[2Kdone | req/s: %.0f | hits: %d | catch-all: %d | seen suppressed: %d | errors: %d | time: %s%s\n",
			reqRate, hits, len(s.catchAll), s.suppressed, s.lastErrors, elapsed.Round(time.Millisecond), progress)
	} else if s.conf.OutputMode != "silent" {
		sep := BANNER_SEP
		footer := BANNER_FOOTER
		resultsLabel := fmt.Sprintf(":: Results     : %d", len(s.Results))
		timeLabel := fmt.Sprintf(":: Time        : %s", elapsed.Round(time.Millisecond))
		speedLabel := fmt.Sprintf(":: Avg speed   : %.0f req/sec", rps)
		catchAllLabel := fmt.Sprintf(":: Catch-all   : %d groups, seen suppressed: %d", len(s.catchAll), s.suppressed)

		if s.conf.Colors {
			sep = ANSI_DIM + BANNER_SEP + ANSI_CLEAR
			footer = ANSI_CYAN + BANNER_FOOTER + ANSI_CLEAR
			resultsLabel = fmt.Sprintf(":: Results     : %s%d%s", ANSI_BRIGHT_GREEN+ANSI_BOLD, len(s.Results), ANSI_CLEAR)
			timeLabel = fmt.Sprintf(":: Time        : %s%s%s", ANSI_CYAN, elapsed.Round(time.Millisecond), ANSI_CLEAR)
			speedLabel = fmt.Sprintf(":: Avg speed   : %s%.0f req/sec%s", ANSI_CYAN, rps, ANSI_CLEAR)
		}

		if s.conf.OutputMode == "live" {
			fmt.Fprintf(os.Stderr, "\r\033[2K")
		}
		fmt.Fprintf(os.Stderr, "\n%s\n", sep)
		fmt.Fprintf(os.Stderr, "%s\n", resultsLabel)
		fmt.Fprintf(os.Stderr, "%s\n", timeLabel)
		fmt.Fprintf(os.Stderr, "%s\n", speedLabel)
		if s.suppressed > 0 {
			fmt.Fprintf(os.Stderr, "%s\n", catchAllLabel)
		}
		fmt.Fprintf(os.Stderr, "%s\n", sep)
		if s.conf.OutputMode == "normal" {
			fmt.Fprintf(os.Stderr, "%s\n", footer)
		}
	}

	if s.conf.OutputFile != "" && s.conf.OutputMode != "silent" {
		saved := fmt.Sprintf(":: Saved to    : %s", s.conf.OutputFile)
		if s.conf.Colors {
			saved = fmt.Sprintf(":: Saved to    : %s%s%s", ANSI_BRIGHT_GREEN, s.conf.OutputFile, ANSI_CLEAR)
		}
		fmt.Fprintf(os.Stderr, "%s\n", saved)
	}

	if s.conf.Json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s.Results)
	}

	return nil
}

func (s *Stdoutput) writeOutput() error {
	f, err := os.Create(s.conf.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file %q: %w", s.conf.OutputFile, err)
	}
	defer f.Close()

	switch strings.ToLower(s.conf.OutputFormat) {
	case "csv", "ecsv":
		fmt.Fprintln(f, "FUZZ,url,redirectlocation,status,length,words,lines,content_type,duration_ms")
		for _, r := range s.Results {
			fmt.Fprintf(f, "%s,%s,%s,%d,%d,%d,%d,%s,%d\n",
				string(r.Input["FUZZ"]), r.Url, r.RedirectLocation,
				r.StatusCode, r.ContentLength, r.ContentWords, r.ContentLines,
				r.ContentType, r.Duration.Milliseconds())
		}
	case "md":
		fmt.Fprintf(f, "# xhacking_z — apifuzz results\n\n**Target:** `%s`  \n**Date:** %s\n\n", s.conf.Url, time.Now().Format(time.RFC3339))
		fmt.Fprintln(f, "| URL | Status | Size | Words | Lines |")
		fmt.Fprintln(f, "|-----|--------|------|-------|-------|")
		for _, r := range s.Results {
			fmt.Fprintf(f, "| `%s` | %d | %d | %d | %d |\n",
				r.Url, r.StatusCode, r.ContentLength,
				r.ContentWords, r.ContentLines)
		}
	default: // json
		type jsonOut struct {
			CommandLine string        `json:"commandline"`
			Time        string        `json:"time"`
			Results     []ffuf.Result `json:"results"`
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonOut{
			Time:    time.Now().Format(time.RFC3339),
			Results: s.Results,
		})
	}
	return nil
}

// Info prints a cyan [INFO] message — always colored for readability.
func (s *Stdoutput) Info(msg string) {
	if s.conf.OutputMode != "normal" || s.conf.Quiet {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\r\033[2K%s[INFO]%s %s\n", ANSI_BRIGHT_CYAN, ANSI_CLEAR, msg)
}

// Error prints a red [ERR] message — always colored.
func (s *Stdoutput) Error(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\r\033[2K%s[ERR] %s %s\n", ANSI_BRIGHT_RED, ANSI_CLEAR, msg)
}

// Warning prints a yellow [WARN] message — always colored.
func (s *Stdoutput) Warning(msg string) {
	if s.conf.OutputMode != "normal" || s.conf.Quiet {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\r\033[2K%s[WARN]%s %s\n", ANSI_YELLOW, ANSI_CLEAR, msg)
}

func (s *Stdoutput) Raw(msg string) { fmt.Fprint(os.Stderr, msg) }

func printOption(colors bool, name, value string) {
	if colors {
		fmt.Fprintf(os.Stderr, " :: [%s%-16s%s] : %s\n", ANSI_CYAN, name, ANSI_CLEAR, value)
	} else {
		fmt.Fprintf(os.Stderr, " :: [%-16s] : %s\n", name, value)
	}
}

func sortedKeys(m map[string]ffuf.FilterProvider) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func shouldPrintCatchAll(seen int64) bool {
	if seen == 5 || seen == 10 || seen == 25 || seen == 50 {
		return true
	}
	return seen > 0 && seen%100 == 0
}

func hostForResult(r ffuf.Result) string {
	if r.Host != "" {
		return r.Host
	}
	u, err := url.Parse(r.Url)
	if err == nil && u.Host != "" {
		return u.Host
	}
	return r.Url
}

func formatBytes(n int64) string {
	return fmt.Sprintf("%d B", n)
}
