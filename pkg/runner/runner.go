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

func (r *SimpleRunner) Run(out ffuf.OutputProvider) error {
        providers := make([]*input.WordlistProvider, 0, len(r.conf.Wordlists))
        for _, wl := range r.conf.Wordlists {
                if !r.conf.Quiet {
                        out.Info(fmt.Sprintf("Loading wordlist: %s", wl))
                }
                p, err := input.NewWordlistProvider(wl, "FUZZ", r.conf.IgnoreComments)
                if err != nil {
                        return err
                }
                providers = append(providers, p)
                if !r.conf.Quiet {
                        out.Info(fmt.Sprintf("Loaded %d words", p.Total()))
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

        // Auto-calibration: send baseline requests with random non-existent paths
        if r.conf.AutoCalibration {
                if !r.conf.Quiet {
                        out.Info("Running auto-calibration...")
                }
                if err := r.autoCalibrate(out); err != nil && !r.conf.Quiet {
                        out.Warning(fmt.Sprintf("Auto-calibration warning: %v", err))
                }
        }

        total := len(words)
        jobs := make(chan string, r.conf.Threads*8)
        var wg sync.WaitGroup
        var foundCount int64
        var doneCount int64
        var errorCount int64

        // WAF/rate-limit detection counters
        var status403Count int64
        var status429Count int64

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
        var progressStop = make(chan struct{})
        go func() {
                ticker := time.NewTicker(100 * time.Millisecond)
                defer ticker.Stop()
                var lastWarn403 int64
                var lastWarn429 int64
                for {
                        select {
                        case <-progressStop:
                                return
                        case <-ticker.C:
                                cur := atomic.LoadInt64(&doneCount)
                                errs := atomic.LoadInt64(&errorCount)
                                found := atomic.LoadInt64(&foundCount)
                                cnt403 := atomic.LoadInt64(&status403Count)
                                cnt429 := atomic.LoadInt64(&status429Count)

                                if !r.conf.Quiet && !r.conf.Json {
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

                                // Warn if WAF/rate-limiting is likely
                                if cur > 50 {
                                        ratio403 := float64(cnt403) / float64(cur)
                                        if ratio403 > 0.80 && cnt403 != lastWarn403 {
                                                lastWarn403 = cnt403
                                                fmt.Fprintf(os.Stderr, "\n\033[33m[WARN] %.0f%% of responses are 403 Forbidden — server may be blocking automated requests (WAF/rate-limit). Try: lower threads (-t 5), add delay (-p 0.5-1.5), use custom headers (-H), or add Authorization token.\033[0m\n", ratio403*100)
                                        }
                                }
                                if cnt429 > 10 && cnt429 != lastWarn429 {
                                        lastWarn429 = cnt429
                                        fmt.Fprintf(os.Stderr, "\n\033[33m[WARN] Received %d × 429 Too Many Requests — server is rate-limiting. Consider: -rate 10, -p 1.0-2.0, or -t 5\033[0m\n", cnt429)
                                }
                        }
                }
        }()

        for i := 0; i < r.conf.Threads; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                case word, ok := <-jobs:
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

                                        res := r.fuzz(word)
                                        atomic.AddInt64(&doneCount, 1)

                                        if res.StatusCode == 0 {
                                                atomic.AddInt64(&errorCount, 1)
                                                if r.conf.StopOnErrors || r.conf.StopOnAll {
                                                        r.conf.Cancel()
                                                        return
                                                }
                                                continue
                                        }

                                        // Track WAF/rate-limit signals
                                        if res.StatusCode == 403 {
                                                atomic.AddInt64(&status403Count, 1)
                                        }
                                        if res.StatusCode == 429 {
                                                atomic.AddInt64(&status429Count, 1)
                                        }

                                        // Stop-on-403 check: if > 95% are 403 after 50+ requests
                                        if r.conf.StopOn403 || r.conf.StopOnAll {
                                                cur := atomic.LoadInt64(&doneCount)
                                                if cur > 50 {
                                                        cnt403 := atomic.LoadInt64(&status403Count)
                                                        if float64(cnt403)/float64(cur) > 0.95 {
                                                                if !r.conf.Quiet {
                                                                        fmt.Fprintf(os.Stderr, "\n[WARN] > 95%% of responses are 403. Stopping (-sf). The server is likely blocking requests.\n")
                                                                }
                                                                r.conf.Cancel()
                                                                return
                                                        }
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

        go func() {
                for _, word := range words {
                        select {
                        case <-ctx.Done():
                                break
                        case jobs <- word:
                        }
                }
                close(jobs)
        }()

        wg.Wait()
        close(progressStop)

        if !r.conf.Quiet {
                fmt.Fprintln(os.Stderr)
                // Final WAF summary
                cnt403 := atomic.LoadInt64(&status403Count)
                cnt429 := atomic.LoadInt64(&status429Count)
                done := atomic.LoadInt64(&doneCount)
                if done > 0 {
                        if float64(cnt403)/float64(done) > 0.50 {
                                fmt.Fprintf(os.Stderr, "[WARN] %d/%d responses were 403 Forbidden. The server may be blocking fuzzing traffic.\n", cnt403, done)
                                fmt.Fprintf(os.Stderr, "       Suggestions: reduce threads (-t 5), add delay (-p 1.0), use a real User-Agent (-H 'User-Agent: Mozilla/5.0 ...'), add Authorization header (-H 'Authorization: Bearer TOKEN')\n")
                        }
                        if cnt429 > 0 {
                                fmt.Fprintf(os.Stderr, "[WARN] %d rate-limit (429) responses received. Use -rate 10 or -p 1.0-2.0 to slow down.\n", cnt429)
                        }
                }
        }

        return out.Finalize()
}

// fuzz sends a request for the given payload, retrying on network errors
// and on rate-limiting responses (429, 503) with exponential backoff.
func (r *SimpleRunner) fuzz(payload string) ffuf.Result {
        maxRetries := r.conf.Retries + 1
        var res ffuf.Result
        for attempt := 0; attempt < maxRetries; attempt++ {
                res = r.doRequest(payload)

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

func (r *SimpleRunner) doRequest(payload string) ffuf.Result {
        // Build target URL, normalizing double slashes that can appear when
        // the user writes e.g. https://example.com//FUZZ
        var encodedPayload string
        if r.conf.Raw {
                // -raw: use payload exactly as-is, no encoding at all
                encodedPayload = payload
        } else {
                // Encode URL-unsafe characters but PRESERVE forward slashes so that
                // path-based wordlist entries like /v1/foo/bar are not mangled into
                // %2Fv1%2Ffoo%2Fbar (which makes the server return 403 instead of 200).
                encodedPayload = encodePayloadPreservingSlashes(payload)
        }
        rawURL := strings.ReplaceAll(r.conf.Url, "FUZZ", encodedPayload)
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

// normalizeURL removes double slashes in the path portion of a URL.
// e.g. https://example.com//v1/foo → https://example.com/v1/foo
func normalizeURL(raw string) string {
        // Split on scheme://host to only clean the path
        schemeEnd := strings.Index(raw, "://")
        if schemeEnd == -1 {
                return raw
        }
        scheme := raw[:schemeEnd+3]
        rest := raw[schemeEnd+3:]

        // Find end of host (first slash after scheme)
        slashIdx := strings.Index(rest, "/")
        if slashIdx == -1 {
                return raw
        }
        host := rest[:slashIdx]
        path := rest[slashIdx:]

        // Collapse consecutive slashes in path (but keep the leading one)
        for strings.Contains(path, "//") {
                path = strings.ReplaceAll(path, "//", "/")
        }

        return scheme + host + path
}

// autoCalibrate sends requests with random non-existent payloads and
// auto-adds size/word/line filters if responses are consistent.
// It also detects if the server is blocking calibration requests.
func (r *SimpleRunner) autoCalibrate(out ffuf.OutputProvider) error {
        const calibrationRounds = 5
        baselines := make([]ffuf.Result, 0, calibrationRounds)

        for i := 0; i < calibrationRounds; i++ {
                payload := randomString(24)
                res := r.doRequest(payload)
                if res.StatusCode != 0 {
                        baselines = append(baselines, res)
                }
                time.Sleep(200 * time.Millisecond)
        }

        if len(baselines) < 3 {
                return fmt.Errorf("not enough calibration responses (got %d/5) — server may be unreachable", len(baselines))
        }

        // Detect if calibration itself is being blocked
        blockedCount := 0
        for _, b := range baselines {
                if b.StatusCode == 403 || b.StatusCode == 429 || b.StatusCode == 503 {
                        blockedCount++
                }
        }
        if blockedCount >= len(baselines)-1 {
                out.Warning(fmt.Sprintf(
                        "Auto-calibration: %d/%d baseline requests returned %d-class responses. "+
                                "The server appears to be blocking requests already. "+
                                "Calibration filters may be inaccurate — consider disabling -ac and using -mc 200 with fewer threads (-t 5) and a delay (-p 1.0).",
                        blockedCount, len(baselines), baselines[0].StatusCode,
                ))
        }

        // Check if sizes are consistent
        sizes := make(map[int64]int)
        words := make(map[int64]int)
        lines := make(map[int64]int)

        for _, b := range baselines {
                sizes[b.ContentLength]++
                words[b.ContentWords]++
                lines[b.ContentLines]++
        }

        threshold := len(baselines) - 1 // most must agree

        for sz, cnt := range sizes {
                if cnt >= threshold {
                        if r.conf.Filters["size"] == nil {
                                r.conf.Filters["size"] = &ffuf.SizeFilterEntry{Value: fmt.Sprintf("%d", sz)}
                                if !r.conf.Quiet {
                                        out.Info(fmt.Sprintf("Auto-calibration: filtering size=%d", sz))
                                }
                        }
                }
        }

        for wc, cnt := range words {
                if cnt >= threshold {
                        if r.conf.Filters["word"] == nil {
                                r.conf.Filters["word"] = &ffuf.WordFilterEntry{Value: fmt.Sprintf("%d", wc)}
                                if !r.conf.Quiet {
                                        out.Info(fmt.Sprintf("Auto-calibration: filtering words=%d", wc))
                                }
                        }
                }
        }

        for lc, cnt := range lines {
                if cnt >= threshold {
                        if r.conf.Filters["line"] == nil {
                                r.conf.Filters["line"] = &ffuf.LineFilterEntry{Value: fmt.Sprintf("%d", lc)}
                                if !r.conf.Quiet {
                                        out.Info(fmt.Sprintf("Auto-calibration: filtering lines=%d", lc))
                                }
                        }
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
