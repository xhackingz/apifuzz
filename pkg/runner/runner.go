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

// baselineResult holds the multi-dimensional response fingerprint of the base URL
// (FUZZ replaced with ""). It powers several false positive validation categories:
//   - Category 2 (SPA/catch-all): size proximity, word/line count
//   - Category 3 (soft redirects/landing pages): title match, SimHash similarity
//   - Category 6 (near-duplicate bodies): SimHash Hamming distance
type baselineResult struct {
        size    int64
        words   int64
        lines   int64
        simhash uint64
        title   string
}

type SimpleRunner struct {
        conf             *ffuf.Config
        client           *http.Client
        startTime        time.Time
        uaIndex          uint64
        sinkMu           sync.Mutex
        sinkCounters     map[string]int64 // redirect Location → hit count (Category 5)
        catchAllMu       sync.Mutex
        catchAllCounters map[catchAllKey]int64
        catchAllSeen     int64
        catchAllUnique   int64
}

type catchAllKey struct {
        host string
        size int64
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

        return &SimpleRunner{
                conf:             conf,
                client:           client,
                startTime:        time.Now(),
                sinkCounters:     make(map[string]int64),
                catchAllCounters: make(map[catchAllKey]int64),
        }
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

        // Per-domain calibration baselines.
        // In single-target mode this is nil and global conf.Filters are used instead.
        // In multi-target mode each domain gets its own noise signature so soft-404
        // behaviour on one subdomain does not mask real findings on another.
        var perDomainFilters map[string][]ffuf.FilterProvider

        if r.conf.AutoCalibration {
                if len(targets) == 1 {
                        // Single target: write calibration results into global Filters as before
                        if !r.conf.Quiet {
                                out.Info("Running auto-calibration...")
                        }
                        if err := r.autoCalibrate(out); err != nil && !r.conf.Quiet {
                                out.Warning(fmt.Sprintf("Auto-calibration warning: %v", err))
                        }
                } else {
                        // Multi-target: calibrate every domain independently and store per-domain
                        if !r.conf.Quiet {
                                out.Info(fmt.Sprintf("Auto-calibrating %d domains (this may take a moment)...", len(targets)))
                        }
                        perDomainFilters = r.autoCalibrateAll(targets, out)
                }
        }

        // Probe every target with random paths to detect catch-all baselines.
        // Runs concurrently (capped at 50 goroutines) so that even large -targets
        // files (hundreds of domains) are probed quickly.
        // Baseline detection works even when the root URL redirects — it uses
        // random-path probes that hit the catch-all handler directly.
        perDomainBaselines := make(map[string]*baselineResult, len(targets))
        {
                var blMu sync.Mutex
                var blWg sync.WaitGroup
                var blDetected int64
                blSem := make(chan struct{}, 50)

                for _, target := range targets {
                        blWg.Add(1)
                        go func(tmpl string) {
                                defer blWg.Done()
                                blSem <- struct{}{}
                                defer func() { <-blSem }()

                                b := r.probeBaseline(tmpl)
                                if b == nil {
                                        return
                                }
                                blMu.Lock()
                                perDomainBaselines[tmpl] = b
                                blMu.Unlock()
                                atomic.AddInt64(&blDetected, 1)
                        }(target)
                }
                blWg.Wait()

                if !r.conf.Quiet {
                        n := atomic.LoadInt64(&blDetected)
                        if n > 0 {
                                out.Info(fmt.Sprintf("Baseline detection: %d/%d targets have a catch-all baseline active (false positives will be suppressed)", n, len(targets)))
                        } else {
                                out.Info("Baseline detection: no catch-all pattern found (targets return unique responses per path)")
                        }
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
                spinner := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
                spin := 0
                for {
                        select {
                        case <-progressStop:
                                return
                        case <-ticker.C:
                                if !r.conf.Quiet && !r.conf.Json && r.conf.OutputMode != "silent" {
                                        cur := atomic.LoadInt64(&doneCount)
                                        errs := atomic.LoadInt64(&errorCount)
                                        found := atomic.LoadInt64(&foundCount)
                                        catchAll := atomic.LoadInt64(&r.catchAllUnique)
                                        catchAllSeen := atomic.LoadInt64(&r.catchAllSeen)
                                        elapsed := time.Since(r.startTime).Seconds()
                                        rps := 0.0
                                        if elapsed > 0 {
                                                rps = float64(cur) / elapsed
                                        }
                                        if r.conf.OutputMode == "live" {
                                                fmt.Fprintf(os.Stderr, "\r\033[2K%c fuzzing... | req/s: %.0f | hits: %d | catch-all: %d | seen suppressed: %d",
                                                        spinner[spin%len(spinner)], rps, found, catchAll, catchAllSeen)
                                                spin++
                                                continue
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

                                        // Per-domain calibration check.
                                        // If this domain was calibrated, test the result against
                                        // its noise baseline before applying global matchers.
                                        if perDomainFilters != nil {
                                                if domFilters, ok := perDomainFilters[job.URLTemplate]; ok {
                                                        noisy := false
                                                        for _, f := range domFilters {
                                                                if matched, err := f.Filter(&res); err == nil && matched {
                                                                        noisy = true
                                                                        break
                                                                }
                                                        }
                                                        if noisy {
                                                                if r.conf.Verbose {
                                                                        out.PrintResult(res, "filtered: matches domain noise baseline (-ac)")
                                                                }
                                                                continue
                                                        }
                                                }
                                        }

                                        // ── Multi-category false positive validation pipeline ────────────
                                        //
                                        // Cat 2 / 3 / 6 — Base URL baseline (SPA, catch-all, soft-redirect,
                                        //                  near-duplicate bodies, landing pages)
                                        if b, ok := perDomainBaselines[job.URLTemplate]; ok {
                                                if matchesBaseline(&res, b) {
                                                        seen := r.recordCatchAll(res)
                                                        if shouldPrintCatchAll(seen) {
                                                                out.CatchAll(catchAllHost(res), res.ContentLength, seen)
                                                        }
                                                        if r.conf.Verbose {
                                                                out.PrintResult(res, "filtered: matches base URL baseline (SPA / soft-redirect / near-duplicate)")
                                                        }
                                                        continue
                                                }
                                        }

                                        // Cat 1 — Soft 404: HTTP 200 with error message in body
                                        if res.HasSoftError {
                                                if r.conf.Verbose {
                                                        out.PrintResult(res, "filtered: soft-404 phrase detected in response body")
                                                }
                                                continue
                                        }

                                        // Cat 3 (extra) — JavaScript / meta soft redirect in body
                                        if res.HasSoftRedir {
                                                if r.conf.Verbose {
                                                        out.PrintResult(res, "filtered: JavaScript/meta soft-redirect detected in response body")
                                                }
                                                continue
                                        }

                                        // Cat 4 — CDN / proxy cache HIT (normalised cached response)
                                        if res.IsCDNHit {
                                                if r.conf.Verbose {
                                                        out.PrintResult(res, "filtered: CDN/proxy cache HIT response")
                                                }
                                                continue
                                        }

                                        // Cat 5 — Redirect sink: same Location seen for too many results
                                        if loc := res.RedirectLocation; loc != "" {
                                                r.sinkMu.Lock()
                                                r.sinkCounters[loc]++
                                                sinkCount := r.sinkCounters[loc]
                                                r.sinkMu.Unlock()
                                                if sinkCount > 10 {
                                                        if r.conf.Verbose {
                                                                out.PrintResult(res, fmt.Sprintf("filtered: redirect sink (%d results share Location: %s)", sinkCount, loc))
                                                        }
                                                        continue
                                                }
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

        if !r.conf.Quiet && r.conf.OutputMode != "silent" {
                fmt.Fprintln(os.Stderr)
        }

        return out.Finalize()
}

func (r *SimpleRunner) recordCatchAll(res ffuf.Result) int64 {
        key := catchAllKey{host: catchAllHost(res), size: res.ContentLength}
        r.catchAllMu.Lock()
        r.catchAllCounters[key]++
        seen := r.catchAllCounters[key]
        r.catchAllMu.Unlock()
        atomic.AddInt64(&r.catchAllSeen, 1)
        if seen == 1 {
                atomic.AddInt64(&r.catchAllUnique, 1)
        }
        return seen
}

func catchAllHost(res ffuf.Result) string {
        if res.Host != "" {
                return res.Host
        }
        if u, err := url.Parse(res.Url); err == nil && u.Host != "" {
                return u.Host
        }
        return res.Url
}

func shouldPrintCatchAll(seen int64) bool {
        switch seen {
        case 5, 10, 25, 50:
                return true
        }
        return seen >= 100 && seen%100 == 0
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
        return r.doRequestWithClient(payload, urlTemplate, r.client)
}

func (r *SimpleRunner) doRequestWithClient(payload, urlTemplate string, client *http.Client) ffuf.Result {
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
        resp, err := client.Do(req)
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

        // ── False positive validation fields ──────────────────────────────────
        // These are computed for every response and consumed by the validation
        // pipeline in Run().  They do not appear in any user-visible output.
        contentType := strings.Split(resp.Header.Get("Content-Type"), ";")[0]
        isHTML := strings.Contains(contentType, "text/html")

        var (
                title        string
                simhash      uint64
                hasSoftError bool
                hasSoftRedir bool
        )
        if isHTML && len(body) > 0 {
                // Limit the slice used for analysis to 64 KB to cap CPU cost.
                analysisBuf := body
                if len(analysisBuf) > 64*1024 {
                        analysisBuf = analysisBuf[:64*1024]
                }
                title = extractTitle(analysisBuf)
                simhash = computeSimHash(analysisBuf)
                hasSoftError = hasSoftErrorPhrase(analysisBuf)
                hasSoftRedir = hasSoftRedirect(analysisBuf)
        }

        // Category 4: CDN / proxy cache hit detection from response headers.
        cdnHit := isCDNHit(resp.Header)

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
                ContentType:      contentType,
                RedirectLocation: redirect,
                Url:              targetURL,
                Duration:         duration,
                Host:             req.URL.Host,
                RetryAfter:       retryAfter,
                SimHash:          simhash,
                Title:            title,
                HasSoftError:     hasSoftError,
                HasSoftRedir:     hasSoftRedir,
                IsCDNHit:         cdnHit,
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

// calibrateTarget sends a small number of requests to provably-nonexistent
// paths on urlTemplate and returns FilterProvider entries that describe the
// domain's noise baseline (soft-404 / generic error page profile).
// Returns nil filters (no error) when the domain returns 401/403 for probes —
// those domains simply can't be calibrated without credentials.
func (r *SimpleRunner) calibrateTarget(urlTemplate string) ([]ffuf.FilterProvider, error) {
        const calibSamples = 3

        type sample struct{ size, words, lines int64 }
        samples := make([]sample, 0, calibSamples)

        for i := 0; i < calibSamples; i++ {
                res := r.doRequest(randomString(24), urlTemplate)
                if res.StatusCode == 0 {
                        return nil, fmt.Errorf("network error during calibration")
                }
                // 401/403 means the domain requires auth — skip calibration silently
                if res.StatusCode == 401 || res.StatusCode == 403 {
                        return nil, nil
                }
                samples = append(samples, sample{res.ContentLength, res.ContentWords, res.ContentLines})
        }

        if len(samples) < calibSamples {
                return nil, fmt.Errorf("insufficient calibration samples")
        }

        allSameSize  := true
        allSameWords := true
        allSameLines := true
        for _, s := range samples[1:] {
                if s.size  != samples[0].size  { allSameSize  = false }
                if s.words != samples[0].words { allSameWords = false }
                if s.lines != samples[0].lines { allSameLines = false }
        }

        var filters []ffuf.FilterProvider
        if allSameSize && samples[0].size > 0 {
                filters = append(filters, &ffuf.SizeFilterEntry{Value: strconv.FormatInt(samples[0].size, 10)})
        } else if allSameWords && samples[0].words > 0 {
                filters = append(filters, &ffuf.WordFilterEntry{Value: strconv.FormatInt(samples[0].words, 10)})
        } else if allSameLines && samples[0].lines > 0 {
                filters = append(filters, &ffuf.LineFilterEntry{Value: strconv.FormatInt(samples[0].lines, 10)})
        }
        return filters, nil
}

// autoCalibrate is the single-target calibration path.
// It calls calibrateTarget and writes the resulting filters into the global
// conf.Filters so that filter.ShouldShow picks them up automatically.
func (r *SimpleRunner) autoCalibrate(out ffuf.OutputProvider) error {
        urlTemplate := r.conf.Url
        if len(r.conf.Targets) > 0 {
                urlTemplate = r.conf.Targets[0]
        }

        filters, err := r.calibrateTarget(urlTemplate)
        if err != nil {
                return err
        }

        for _, f := range filters {
                switch v := f.(type) {
                case *ffuf.SizeFilterEntry:
                        r.conf.Filters["size"] = v
                        if !r.conf.Quiet {
                                out.Info(fmt.Sprintf("Auto-filter: response size %s bytes", v.Value))
                        }
                case *ffuf.WordFilterEntry:
                        r.conf.Filters["words"] = v
                        if !r.conf.Quiet {
                                out.Info(fmt.Sprintf("Auto-filter: response words %s", v.Value))
                        }
                case *ffuf.LineFilterEntry:
                        r.conf.Filters["lines"] = v
                        if !r.conf.Quiet {
                                out.Info(fmt.Sprintf("Auto-filter: response lines %s", v.Value))
                        }
                }
        }
        return nil
}

// autoCalibrateAll runs calibrateTarget concurrently for every domain in targets
// and returns a map[urlTemplate]→[]FilterProvider.  Domains that return 401/403
// for probes, or have dynamic error pages, simply have no entry in the map and
// are fuzzed without a baseline filter.
func (r *SimpleRunner) autoCalibrateAll(targets []string, out ffuf.OutputProvider) map[string][]ffuf.FilterProvider {
        result := make(map[string][]ffuf.FilterProvider, len(targets))
        var mu sync.Mutex

        // Limit concurrent calibration goroutines to avoid overwhelming the network
        const concurrency = 50
        sem := make(chan struct{}, concurrency)

        var wg sync.WaitGroup
        var calibrated int64

        for _, target := range targets {
                wg.Add(1)
                go func(urlTemplate string) {
                        defer wg.Done()
                        sem <- struct{}{}
                        defer func() { <-sem }()

                        filters, err := r.calibrateTarget(urlTemplate)
                        if err != nil || len(filters) == 0 {
                                return
                        }
                        mu.Lock()
                        result[urlTemplate] = filters
                        mu.Unlock()
                        atomic.AddInt64(&calibrated, 1)
                }(target)
        }
        wg.Wait()

        if !r.conf.Quiet {
                n := atomic.LoadInt64(&calibrated)
                out.Info(fmt.Sprintf("Auto-calibration complete: %d/%d domains have a soft-404 baseline active", n, len(targets)))
        }
        return result
}

// probeBaseline detects the noise baseline for a target by sending a small
// number of requests with provably-nonexistent random paths.  If those probes
// return consistent responses — same size, SimHash, or word/line count — the
// target is a catch-all and the shared fingerprint is used to suppress false
// positives during fuzzing.
//
// This approach is robust against the most common failure mode of base-URL-
// based probing: when the root URL redirects (login walls, marketing homepages,
// API gateway catch-alls), a base-URL probe returns non-200 and no baseline
// is set.  Random paths hit the catch-all handler directly.
func (r *SimpleRunner) probeBaseline(urlTemplate string) *baselineResult {
        const numProbes = 3

        type snap struct {
                size, words, lines int64
                simhash            uint64
                title              string
        }

        baselineClient := *r.client
        baselineClient.CheckRedirect = nil

        snaps := make([]snap, 0, numProbes)
        for i := 0; i < numProbes; i++ {
                res := r.doRequestWithClient(randomString(24), urlTemplate, &baselineClient)
                if res.StatusCode == 0 {
                        continue
                }
                snaps = append(snaps, snap{
                        size:    res.ContentLength,
                        words:   res.ContentWords,
                        lines:   res.ContentLines,
                        simhash: res.SimHash,
                        title:   res.Title,
                })
        }

        if len(snaps) == 0 {
                return nil
        }

        first := snaps[0]

        if len(snaps) == 1 {
                return &baselineResult{size: first.size, words: first.words, lines: first.lines, simhash: first.simhash, title: first.title}
        }

        // Consistent byte size — strongest signal, use it directly.
        allSameSize := true
        for _, s := range snaps[1:] {
                if s.size != first.size {
                        allSameSize = false
                        break
                }
        }
        if allSameSize && first.size > 0 {
                return &baselineResult{size: first.size, words: first.words, lines: first.lines, simhash: first.simhash, title: first.title}
        }

        // Structurally near-identical bodies (SimHash Hamming distance ≤ 5).
        allSimilar := true
        for _, s := range snaps[1:] {
                if s.simhash == 0 || hammingDistance(s.simhash, first.simhash) > 5 {
                        allSimilar = false
                        break
                }
        }
        if allSimilar && first.simhash != 0 {
                return &baselineResult{size: first.size, words: first.words, lines: first.lines, simhash: first.simhash, title: first.title}
        }

        // Consistent word count — fallback for pages with dynamic whitespace.
        allSameWords := true
        for _, s := range snaps[1:] {
                if s.words != first.words {
                        allSameWords = false
                        break
                }
        }
        if allSameWords && first.words > 0 {
                return &baselineResult{size: first.size, words: first.words, lines: first.lines, simhash: first.simhash, title: first.title}
        }

        // Consistent line count — final fallback.
        allSameLines := true
        for _, s := range snaps[1:] {
                if s.lines != first.lines {
                        allSameLines = false
                        break
                }
        }
        if allSameLines && first.lines > 0 {
                return &baselineResult{size: first.size, words: first.words, lines: first.lines, simhash: first.simhash, title: first.title}
        }

        return &baselineResult{size: first.size, words: first.words, lines: first.lines, simhash: first.simhash, title: first.title}
}

// matchesBaseline returns true when a fuzz result looks identical or near-
// identical to the base URL baseline, indicating a SPA catch-all, soft-
// redirect, landing page, or CDN-cached fallback.
//
// Matching criteria — any one is sufficient to classify as false positive:
//   - Exact or ±5% size match (Categories 2, 3)
//   - Same word count or line count (fallback for dynamic content size variance)
//   - SimHash Hamming distance ≤ 5 bits (Category 6 near-duplicate detection)
//   - Title tag exact match against the base URL (Category 3)
func matchesBaseline(res *ffuf.Result, b *baselineResult) bool {
        if b == nil {
                return false
        }
        // Size proximity check (Categories 2 & 3)
        if b.size > 0 {
                diff := res.ContentLength - b.size
                if diff < 0 {
                        diff = -diff
                }
                if diff == 0 || float64(diff)/float64(b.size) <= 0.05 {
                        return true
                }
        }
        // Word / line count fallback
        if b.words > 0 && res.ContentWords == b.words {
                return true
        }
        if b.lines > 0 && res.ContentLines == b.lines {
                return true
        }
        // SimHash near-duplicate check (Category 6)
        // Hamming distance ≤ 5 bits out of 64 means >92% structural similarity.
        if b.simhash != 0 && res.SimHash != 0 {
                if hammingDistance(res.SimHash, b.simhash) <= 5 {
                        return true
                }
        }
        // Title tag match (Category 3 — soft redirects / landing pages)
        if b.title != "" && res.Title != "" && b.title == res.Title {
                return true
        }
        return false
}

// ── False positive detection helpers ─────────────────────────────────────────

// stripHTMLTags removes all HTML/XML tags from body, returning plain text.
// A space is emitted in place of each closing angle bracket so that adjacent
// words from different elements are not merged into a single token.
func stripHTMLTags(body []byte) []byte {
        out := make([]byte, 0, len(body))
        inTag := false
        for _, b := range body {
                switch {
                case b == '<':
                        inTag = true
                case b == '>':
                        inTag = false
                        out = append(out, ' ')
                case !inTag:
                        out = append(out, b)
                }
        }
        return out
}

// extractTitle returns the inner text of the first <title> element found in body.
func extractTitle(body []byte) string {
        lower := bytes.ToLower(body)
        start := bytes.Index(lower, []byte("<title>"))
        if start == -1 {
                return ""
        }
        start += 7
        end := bytes.Index(lower[start:], []byte("</title>"))
        if end == -1 {
                return ""
        }
        return strings.TrimSpace(string(body[start : start+end]))
}

// fnv64a returns the FNV-1a 64-bit hash of the given string.
func fnv64a(s string) uint64 {
        var h uint64 = 14695981039346656037
        for i := 0; i < len(s); i++ {
                h ^= uint64(s[i])
                h *= 1099511628211
        }
        return h
}

// computeSimHash computes a 64-bit SimHash fingerprint of the response body.
// HTML tags are stripped first so structural content (words) is compared,
// not raw markup.  Short tokens (< 3 chars) are skipped as noise.
func computeSimHash(body []byte) uint64 {
        text := stripHTMLTags(body)
        var v [64]int32
        for _, word := range strings.Fields(strings.ToLower(string(text))) {
                if len(word) < 3 {
                        continue
                }
                h := fnv64a(word)
                for i := 0; i < 64; i++ {
                        if (h>>uint(i))&1 == 1 {
                                v[i]++
                        } else {
                                v[i]--
                        }
                }
        }
        var fp uint64
        for i := 0; i < 64; i++ {
                if v[i] > 0 {
                        fp |= 1 << uint(i)
                }
        }
        return fp
}

// hammingDistance returns the number of differing bits between two uint64 values.
func hammingDistance(a, b uint64) int {
        x := a ^ b
        n := 0
        for x != 0 {
                n += int(x & 1)
                x >>= 1
        }
        return n
}

// hasSoftErrorPhrase returns true if the stripped body contains common phrases
// that indicate a soft-404 response (HTTP 200 with an error message inside).
// Only the first 64 KB of the body is inspected.
func hasSoftErrorPhrase(body []byte) bool {
        text := strings.ToLower(string(stripHTMLTags(body)))
        phrases := []string{
                "page not found",
                "404 not found",
                "error 404",
                "does not exist",
                "no longer available",
                "resource not found",
                "endpoint not found",
                "route not found",
                "path not found",
                "the page you were looking for",
                "the requested url was not found",
                "could not be found",
        }
        for _, p := range phrases {
                if strings.Contains(text, p) {
                        return true
                }
        }
        return false
}

// hasSoftRedirect returns true if the response body contains JavaScript-based
// or meta-tag soft redirect signals — a 200 response that immediately navigates
// the browser elsewhere without issuing a real HTTP redirect.
func hasSoftRedirect(body []byte) bool {
        lower := strings.ToLower(string(body))
        patterns := []string{
                "window.location",
                "location.href",
                "location.replace(",
                "location.assign(",
                `<meta http-equiv="refresh"`,
                `<meta http-equiv='refresh'`,
        }
        for _, p := range patterns {
                if strings.Contains(lower, p) {
                        return true
                }
        }
        return false
}

// isCDNHit returns true if the response headers indicate a CDN or reverse-proxy
// cache HIT.  Cache-normalised responses return the same stored object for every
// path, making them a source of false positives.
func isCDNHit(header http.Header) bool {
        xCache := strings.ToLower(header.Get("X-Cache"))
        cfCache := strings.ToLower(header.Get("CF-Cache-Status"))
        xProxy := strings.ToLower(header.Get("X-Proxy-Cache"))
        fastly := strings.ToLower(header.Get("X-Served-By"))

        if strings.Contains(xCache, "hit") {
                return true
        }
        if cfCache == "hit" {
                return true
        }
        if strings.Contains(xProxy, "hit") {
                return true
        }
        // Fastly and similar CDNs set X-Served-By to an edge-node name when serving
        // from cache — combined with a non-zero Age header this is a reliable signal.
        if fastly != "" {
                age := strings.TrimSpace(header.Get("Age"))
                if age != "" && age != "0" {
                        return true
                }
        }
        // Generic: non-zero Age header indicates a shared cache hit on any proxy.
        if age := strings.TrimSpace(header.Get("Age")); age != "" && age != "0" {
                return true
        }
        return false
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
