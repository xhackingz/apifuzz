package runner

import (
        "bufio"
        "bytes"
        "compress/flate"
        "compress/gzip"
        "context"
        "crypto/rand"
        "crypto/tls"
        "encoding/hex"
        "fmt"
        "io"
        "math"
        "net/http"
        "net/url"
        "os"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "apifuzz/pkg/ffuf"
        "apifuzz/pkg/filter"
        "apifuzz/pkg/input"
)

// realisticUserAgents rotates through common browser UAs to avoid bot detection.
var realisticUserAgents = []string{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
}

// fuzzJob carries one unit of work: a word to inject and the URL template to inject it into.
// Using a struct instead of a plain string allows multi-target mode to route each word
// to the correct domain without duplicating the entire wordlist per target.
type fuzzJob struct {
        Word        string
        URLTemplate string
}

type SimpleRunner struct {
        conf      *ffuf.Config
        client    *http.Client
        startTime time.Time
        uaIndex   uint64
}

func NewSimpleRunner(conf *ffuf.Config) *SimpleRunner {
        transport := &http.Transport{
                MaxIdleConns:          conf.Threads * 4,
                MaxIdleConnsPerHost:   conf.Threads * 2,
                MaxConnsPerHost:       conf.Threads * 2,
                IdleConnTimeout:       90 * time.Second,
                TLSHandshakeTimeout:   10 * time.Second,
                ResponseHeaderTimeout: time.Duration(conf.Timeout) * time.Second,
                TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
                DisableKeepAlives:     false,
                DisableCompression:    false,
        }

        if conf.ProxyURL != "" {
                if pu, err := url.Parse(conf.ProxyURL); err == nil {
                        transport.Proxy = http.ProxyURL(pu)
                }
        }

        client := &http.Client{
                Transport: transport,
                Timeout:   time.Duration(conf.Timeout) * time.Second,
        }

        if !conf.FollowRedirects {
                client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
                        return http.ErrUseLastResponse
                }
        }

        return &SimpleRunner{conf: conf, client: client, startTime: time.Now()}
}

const defaultWordlistURL = "https://raw.githubusercontent.com/xhackingz/apifuzz/refs/heads/master/wordlists/ultimate_fuzz_master.txt"

func (r *SimpleRunner) Run(out ffuf.OutputProvider) error {
        wordlistSources := r.conf.Wordlists
        if len(wordlistSources) == 0 {
                wordlistSources = []string{defaultWordlistURL}
        }

        providers := make([]*input.WordlistProvider, 0, len(wordlistSources))
        for _, wl := range wordlistSources {
                p, err := input.NewWordlistProvider(wl, "FUZZ", r.conf.IgnoreComments)
                if err != nil {
                        return err
                }
                providers = append(providers, p)
                if !r.conf.Quiet {
                        out.Info(fmt.Sprintf("Loaded %d words from: %s", p.Total(), wl))
                }
        }
        if len(providers) == 0 {
                return fmt.Errorf("no wordlist loaded")
        }

        words := providers[0].Words()
        if len(r.conf.Extensions) > 0 {
                expanded := make([]string, 0, len(words)*(len(r.conf.Extensions)+1))
                for _, w := range words {
                        if !r.conf.DirSearchCompat {
                                expanded = append(expanded, w)
                        }
                        for _, ext := range r.conf.Extensions {
                                expanded = append(expanded, w+ext)
                        }
                }
                words = expanded
        }

        // Build the list of URL templates to fuzz.
        // In single-target mode this is just [conf.Url].
        // In multi-target mode it is every URL from the -targets file.
        targets := []string{r.conf.Url}
        if len(r.conf.Targets) > 0 {
                targets = r.conf.Targets
        }

        // Auto-calibration: run against the first (or only) target
        if r.conf.AutoCalibration {
                if !r.conf.Quiet {
                        out.Info("Running auto-calibration...")
                }
                if err := r.autoCalibrate(out); err != nil && !r.conf.Quiet {
                        out.Warning(fmt.Sprintf("Auto-calibration warning: %v", err))
                }
        }

        // All setup done — print the table header now so results appear cleanly below it.
        if !r.conf.Quiet && !r.conf.Json {
                out.PrintTableHeader()
        }

        // Total jobs = words × targets (interleaved)
        total := len(words) * len(targets)
        jobs := make(chan fuzzJob, r.conf.Threads*8)

        var wg sync.WaitGroup
        var foundCount int64
        var doneCount int64
        var errorCount int64

        ctx := r.conf.Context
        if r.conf.MaxTime > 0 {
                var cancel context.CancelFunc
                ctx, cancel = context.WithTimeout(ctx, time.Duration(r.conf.MaxTime)*time.Second)
                defer cancel()
        }

        // Rate limiter
        var rateLimiter <-chan time.Time
        if r.conf.Rate > 0 {
                interval := time.Duration(float64(time.Second) / float64(r.conf.Rate))
                tick := time.NewTicker(interval)
                defer tick.Stop()
                rateLimiter = tick.C
        }

        minDelay, maxDelay := parseDelay(r.conf.Delay)

        r.startTime = time.Now()

        // Progress ticker
        progressStop := make(chan struct{})
        go func() {
                ticker := time.NewTicker(100 * time.Millisecond)
                defer ticker.Stop()
                for {
                        select {
                        case <-progressStop:
                                return
                        case <-ticker.C:
                                if !r.conf.Quiet && !r.conf.Json {
                                        cur := atomic.LoadInt64(&doneCount)
                                        errs := atomic.LoadInt64(&errorCount)
                                        found := atomic.LoadInt64(&foundCount)
                                        elapsed := time.Since(r.startTime).Seconds()
                                        rps := 0.0
                                        if elapsed > 0 {
                                                rps = float64(cur) / elapsed
                                        }
                                        pct := 0.0
                                        if total > 0 {
                                                pct = float64(cur) / float64(total) * 100
                                        }
                                        eta := ""
                                        if rps > 0 && cur < int64(total) {
                                                remaining := float64(int64(total)-cur) / rps
                                                eta = fmt.Sprintf(" :: ETA: %s", formatDuration(remaining))
                                        }
                                        fmt.Fprintf(os.Stderr, "\r\033[2K:: Progress: [%d/%d] (%.1f%%) :: Found: %d :: %.0f req/sec :: Errors: %d%s",
                                                cur, total, pct, found, rps, errs, eta)
                                }
                        }
                }
        }()

        // Worker goroutines — each picks jobs from the shared channel.
        // Because jobs are interleaved across all targets, every worker
        // naturally hits all domains concurrently.
        for i := 0; i < r.conf.Threads; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                case job, ok := <-jobs:
                                        if !ok {
                                                return
                                        }
                                        if rateLimiter != nil {
                                                select {
                                                case <-rateLimiter:
                                                case <-ctx.Done():
                                                        return
                                                }
                                        }
                                        if minDelay > 0 {
                                                d := minDelay
                                                if maxDelay > minDelay {
                                                        jitter := time.Duration(float64(maxDelay-minDelay) * randFloat())
                                                        d += jitter
                                                }
                                                time.Sleep(d)
                                        }

                                        res := r.fuzz(job)
                                        atomic.AddInt64(&doneCount, 1)

                                        if res.StatusCode == 0 {
                                                atomic.AddInt64(&errorCount, 1)
                                                if r.conf.StopOnErrors || r.conf.StopOnAll {
                                                        r.conf.Cancel()
                                                        return
                                                }
                                                continue
                                        }

                                        show, reason := filter.ShouldShow(r.conf, &res)
                                        if show {
                                                atomic.AddInt64(&foundCount, 1)
                                                out.Result(res)
                                        } else if r.conf.Verbose {
                                                out.PrintResult(res, reason)
                                        }
                                }
                        }
                }()
        }

        // Job feeder: interleave targets for each word so all domains are
        // hit simultaneously rather than one domain at a time.
        // Pattern: word1→target1, word1→target2, ..., word2→target1, word2→target2, ...
        go func() {
                defer close(jobs)
                for _, word := range words {
                        for _, target := range targets {
                                select {
                                case <-ctx.Done():
                                        return
                                case jobs <- fuzzJob{Word: word, URLTemplate: target}:
                                }
                        }
                }
        }()

        wg.Wait()
        close(progressStop)

        if !r.conf.Quiet {
                fmt.Fprintln(os.Stderr)
        }

        return out.Finalize()
}

// fuzz sends a request for the given job, retrying on network errors
// and on rate-limiting responses (429, 503) with exponential backoff.
func (r *SimpleRunner) fuzz(job fuzzJob) ffuf.Result {
        maxRetries := r.conf.Retries + 1
        var res ffuf.Result
        for attempt := 0; attempt < maxRetries; attempt++ {
                res = r.doRequest(job.Word, job.URLTemplate)

                // Retry on network error (status 0)
                if res.StatusCode == 0 {
                        if attempt < maxRetries-1 {
                                backoff := time.Duration(math.Pow(2, float64(attempt))*200) * time.Millisecond
                                time.Sleep(backoff)
                        }
                        continue
                }

                // Retry on rate-limit or temporary server error
                if res.StatusCode == 429 || res.StatusCode == 503 {
                        if attempt < maxRetries-1 {
                                backoff := time.Duration(math.Pow(2, float64(attempt))*500) * time.Millisecond
                                // Honor Retry-After header if present
                                if ra := res.RetryAfter; ra > 0 {
                                        backoff = time.Duration(ra) * time.Second
                                }
                                if r.conf.Debug {
                                        fmt.Fprintf(os.Stderr, "\n[DEBUG] %d response for %s — waiting %s before retry %d/%d\n",
                                                res.StatusCode, res.Url, backoff, attempt+1, maxRetries-1)
                                }
                                time.Sleep(backoff)
                                continue
                        }
                }

                return res
        }
        return res
}

func (r *SimpleRunner) nextUserAgent() string {
        idx := atomic.AddUint64(&r.uaIndex, 1)
        return realisticUserAgents[idx%uint64(len(realisticUserAgents))]
}

// doRequest performs one HTTP request, substituting payload into urlTemplate at the FUZZ keyword.
func (r *SimpleRunner) doRequest(payload, urlTemplate string) ffuf.Result {
        var encodedPayload string
        if r.conf.Raw {
                encodedPayload = payload
        } else {
                // Encode URL-unsafe characters but PRESERVE forward slashes so that
                // path-based wordlist entries like /v1/foo/bar are not mangled into
                // %2Fv1%2Ffoo%2Fbar (which makes servers return 403 instead of 200).
                encodedPayload = encodePayloadPreservingSlashes(payload)
        }
        rawURL := strings.ReplaceAll(urlTemplate, "FUZZ", encodedPayload)
        targetURL := normalizeURL(rawURL)

        bodyStr := strings.ReplaceAll(r.conf.Data, "FUZZ", payload)

        var reqBody io.Reader
        if bodyStr != "" {
                reqBody = strings.NewReader(bodyStr)
        }

        req, err := http.NewRequestWithContext(r.conf.Context, r.conf.Method, targetURL, reqBody)
        if err != nil {
                return ffuf.Result{Url: targetURL, Input: map[string][]byte{"FUZZ": []byte(payload)}}
        }

        // Use a rotating realistic User-Agent unless the caller already set one
        if _, userSet := r.conf.Headers["User-Agent"]; !userSet {
                req.Header.Set("User-Agent", r.nextUserAgent())
        }
        // Send the full set of headers a real browser sends.
        // AWS WAF and other bot-detection systems fingerprint requests by
        // checking for the presence (and order) of these headers.
        req.Header.Set("Accept", "application/json, text/html, */*;q=0.9")
        req.Header.Set("Accept-Language", "en-US,en;q=0.9")
        req.Header.Set("Accept-Encoding", "gzip, deflate, br")
        req.Header.Set("Connection", "keep-alive")
        req.Header.Set("Cache-Control", "no-cache")
        req.Header.Set("Pragma", "no-cache")
        req.Header.Set("Sec-Fetch-Dest", "empty")
        req.Header.Set("Sec-Fetch-Mode", "cors")
        req.Header.Set("Sec-Fetch-Site", "none")
        req.Header.Set("Sec-Ch-Ua", `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`)
        req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
        req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)

        // User-supplied headers override the defaults above
        for k, v := range r.conf.Headers {
                req.Header.Set(k, v)
        }
        if bodyStr != "" && req.Header.Get("Content-Type") == "" {
                req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        }

        if r.conf.Debug {
                fmt.Fprintf(os.Stderr, "\n[DEBUG] --> %s %s\n", req.Method, targetURL)
                for k, vv := range req.Header {
                        fmt.Fprintf(os.Stderr, "[DEBUG]     %s: %s\n", k, strings.Join(vv, ", "))
                }
                if bodyStr != "" {
                        fmt.Fprintf(os.Stderr, "[DEBUG]     Body: %s\n", bodyStr)
                }
        }

        start := time.Now()
        resp, err := r.client.Do(req)
        duration := time.Since(start)

        if err != nil {
                if r.conf.Debug {
                        fmt.Fprintf(os.Stderr, "[DEBUG] <-- ERROR: %v\n", err)
                }
                return ffuf.Result{Url: targetURL, Input: map[string][]byte{"FUZZ": []byte(payload)}}
        }
        defer resp.Body.Close()

        var buf bytes.Buffer
        if !r.conf.IgnoreBody {
                bodyReader := resp.Body
                // Decompress manually because we explicitly set Accept-Encoding,
                // which tells Go's transport NOT to decompress automatically.
                switch resp.Header.Get("Content-Encoding") {
                case "gzip":
                        gr, err := gzip.NewReader(resp.Body)
                        if err == nil {
                                bodyReader = gr
                                defer gr.Close()
                        }
                case "deflate":
                        bodyReader = flate.NewReader(resp.Body)
                        defer bodyReader.Close()
                }
                limitedReader := io.LimitReader(bodyReader, 10*1024*1024) // 10 MB max
                io.Copy(&buf, limitedReader)
        }

        body := buf.Bytes()
        words, lines := countWordsLines(body)
        redirect := resp.Header.Get("Location")

        // Parse Retry-After header (seconds or HTTP-date — we only handle seconds)
        var retryAfter int64
        if ra := resp.Header.Get("Retry-After"); ra != "" {
                if n, err := strconv.ParseInt(strings.TrimSpace(ra), 10, 64); err == nil {
                        retryAfter = n
                }
        }

        if r.conf.Debug {
                fmt.Fprintf(os.Stderr, "[DEBUG] <-- %d | size=%d | words=%d | lines=%d | time=%dms\n",
                        resp.StatusCode, len(body), words, lines, duration.Milliseconds())
                for k, vv := range resp.Header {
                        fmt.Fprintf(os.Stderr, "[DEBUG]     %s: %s\n", k, strings.Join(vv, ", "))
                }
                if len(body) > 0 {
                        preview := body
                        if len(preview) > 512 {
                                preview = preview[:512]
                        }
                        fmt.Fprintf(os.Stderr, "[DEBUG]     Body preview: %s\n", strings.ReplaceAll(string(preview), "\n", " "))
                }
        }

        return ffuf.Result{
                Input:            map[string][]byte{"FUZZ": []byte(payload)},
                StatusCode:       int64(resp.StatusCode),
                ContentLength:    int64(len(body)),
                ContentWords:     int64(words),
                ContentLines:     int64(lines),
                ContentType:      strings.Split(resp.Header.Get("Content-Type"), ";")[0],
                RedirectLocation: redirect,
                Url:              targetURL,
                Duration:         duration,
                Host:             req.URL.Host,
                RetryAfter:       retryAfter,
        }
}

// encodePayloadPreservingSlashes encodes characters that are unsafe in URLs
// but intentionally keeps forward slashes unencoded. This is critical for
// path-based wordlists where entries like /v1/foo/bar must stay as real path
// separators — using url.PathEscape would turn them into %2Fv1%2Ffoo%2Fbar,
// which servers treat as a literal string (not a path), causing 403 responses
// instead of the expected 200.
func encodePayloadPreservingSlashes(payload string) string {
        var buf strings.Builder
        buf.Grow(len(payload))
        for i := 0; i < len(payload); i++ {
                c := payload[i]
                switch {
                case c == '/' || c == '-' || c == '_' || c == '.' || c == '~':
                        buf.WriteByte(c)
                case c >= 'a' && c <= 'z':
                        buf.WriteByte(c)
                case c >= 'A' && c <= 'Z':
                        buf.WriteByte(c)
                case c >= '0' && c <= '9':
                        buf.WriteByte(c)
                default:
                        fmt.Fprintf(&buf, "%%%02X", c)
                }
        }
        return buf.String()
}

// normalizeURL collapses double-slashes in the path that can appear when
// the user writes e.g. https://example.com//FUZZ and the payload is empty.
func normalizeURL(raw string) string {
        // Only collapse // in the path portion, not in the scheme (https://)
        if idx := strings.Index(raw, "://"); idx >= 0 {
                scheme := raw[:idx+3]
                rest := raw[idx+3:]
                for strings.Contains(rest, "//") {
                        rest = strings.ReplaceAll(rest, "//", "/")
                }
                return scheme + rest
        }
        return raw
}

// autoCalibrate sends baseline requests and sets filters for responses that
// match the baseline (soft 404s, generic error pages, etc.).
func (r *SimpleRunner) autoCalibrate(out ffuf.OutputProvider) error {
        const calibSamples = 5

        // Use the first configured target for calibration
        urlTemplate := r.conf.Url
        if len(r.conf.Targets) > 0 {
                urlTemplate = r.conf.Targets[0]
        }

        type sample struct {
                size, words, lines int64
        }
        samples := make([]sample, 0, calibSamples)

        for i := 0; i < calibSamples; i++ {
                res := r.doRequest(randomString(24), urlTemplate)
                if res.StatusCode == 0 {
                        return fmt.Errorf("calibration requests are failing (network error) — server may be unreachable")
                }
                if res.StatusCode == 403 {
                        return fmt.Errorf("calibration requests returned 403 Forbidden — the server is blocking requests. Consider disabling -ac or adding an Authorization header")
                }
                samples = append(samples, sample{res.ContentLength, res.ContentWords, res.ContentLines})
        }

        if len(samples) == 0 {
                return fmt.Errorf("no calibration samples collected")
        }

        // If all samples share the same size, add a size filter
        allSameSize := true
        allSameWords := true
        allSameLines := true
        for _, s := range samples[1:] {
                if s.size != samples[0].size {
                        allSameSize = false
                }
                if s.words != samples[0].words {
                        allSameWords = false
                }
                if s.lines != samples[0].lines {
                        allSameLines = false
                }
        }

        if allSameSize && samples[0].size > 0 {
                r.conf.Filters["size"] = &ffuf.SizeFilterEntry{Value: strconv.FormatInt(samples[0].size, 10)}
                if !r.conf.Quiet {
                        out.Info(fmt.Sprintf("Auto-filter: response size %d bytes", samples[0].size))
                }
        } else if allSameWords && samples[0].words > 0 {
                r.conf.Filters["words"] = &ffuf.WordFilterEntry{Value: strconv.FormatInt(samples[0].words, 10)}
                if !r.conf.Quiet {
                        out.Info(fmt.Sprintf("Auto-filter: response words %d", samples[0].words))
                }
        } else if allSameLines && samples[0].lines > 0 {
                r.conf.Filters["lines"] = &ffuf.LineFilterEntry{Value: strconv.FormatInt(samples[0].lines, 10)}
                if !r.conf.Quiet {
                        out.Info(fmt.Sprintf("Auto-filter: response lines %d", samples[0].lines))
                }
        }

        return nil
}

func countWordsLines(body []byte) (int, int) {
        scanner := bufio.NewScanner(bytes.NewReader(body))
        scanner.Buffer(make([]byte, 512*1024), 512*1024)
        lines, words := 0, 0
        for scanner.Scan() {
                lines++
                words += len(strings.Fields(scanner.Text()))
        }
        return words, lines
}

func parseDelay(s string) (time.Duration, time.Duration) {
        if s == "" {
                return 0, 0
        }
        parts := strings.SplitN(s, "-", 2)
        parse := func(v string) time.Duration {
                v = strings.TrimSpace(v)
                var f float64
                fmt.Sscanf(v, "%f", &f)
                return time.Duration(f * float64(time.Second))
        }
        if len(parts) == 2 {
                return parse(parts[0]), parse(parts[1])
        }
        d := parse(parts[0])
        return d, d
}

func formatDuration(secs float64) string {
        if secs < 60 {
                return fmt.Sprintf("%.0fs", secs)
        }
        if secs < 3600 {
                return fmt.Sprintf("%.0fm%.0fs", math.Floor(secs/60), math.Mod(secs, 60))
        }
        return fmt.Sprintf("%.0fh%.0fm", math.Floor(secs/3600), math.Floor(math.Mod(secs, 3600)/60))
}

func randomString(n int) string {
        b := make([]byte, n/2)
        rand.Read(b)
        return hex.EncodeToString(b)
}

func randFloat() float64 {
        b := make([]byte, 8)
        rand.Read(b)
        return float64(b[0]) / 255.0
}
