# xhacking_z | apifuzz

A fast, production-grade API fuzzing tool built for real-world targets — handles WAF detection, rate limiting, bot-detection bypass, and a full six-category false positive validation engine that eliminates noise automatically.

Written in Go by **xhacking_z**.

> Default wordlist: [ultimate_fuzz_master.txt](https://raw.githubusercontent.com/xhackingz/apifuzz/master/wordlists/ultimate_fuzz_master.txt) (239,000+ entries)

---

## Why apifuzz is different

Most fuzzers match on HTTP status code alone. That means anything returning `200 OK` is logged as a hit — even if the `200` is a marketing page, an SPA shell, a CDN cache dump, or a "Page Not Found" message rendered inside a `200` envelope.

**apifuzz eliminates all of that automatically.** Before the first fuzz request is sent, it fingerprints the target and runs every response through a six-category false positive validation pipeline. You get only real endpoint discoveries.

---

## False Positive Validation Engine

Six categories of false positives are detected and suppressed — no flags required, no manual rules per site.

### Category 1 — Soft 404s
HTTP `200` responses that contain error text in the body ("Page not found", "Route not found", "Does not exist", etc.). The tool scans the stripped HTML body for a curated set of error phrases and suppresses the result.

### Category 2 — SPA / Catch-all routing
Single-page apps and catch-all servers return the same `index.html` for every path. Before fuzzing starts, apifuzz fetches the base URL and records its response size, word count, and line count. Any fuzz response within ±5% of that fingerprint is suppressed — across every domain in multi-target mode independently.

### Category 3 — Soft redirects / landing pages
Servers that return `200` with a marketing page or "service moved" message (like the Intuit Online Payroll example). Detected via two signals: HTML `<title>` tag match against the base URL fingerprint, and JavaScript / meta-tag soft-redirect patterns (`window.location`, `location.href`, `<meta http-equiv="refresh">`).

### Category 4 — CDN / proxy cache normalization
CDN edge nodes serve the same cached object for every cache-miss path. Detected from response headers: `X-Cache: HIT`, `CF-Cache-Status: HIT`, `X-Proxy-Cache: HIT`, non-zero `Age` header combined with `X-Served-By`. Cache-HIT responses are suppressed.

### Category 5 — Redirect sink detection
When a server redirects every unknown path to the same destination (a login page, a 404 page, a catch-all), the `Location` header repeats identically across all results. apifuzz tracks the frequency of each redirect destination. Once a `Location` value appears more than 10 times, all subsequent results with that destination are suppressed as a redirect sink.

### Category 6 — Near-duplicate body detection (SimHash)
Pages with minor dynamic content — timestamps, session tokens, nonces — vary slightly in byte size but are structurally identical. apifuzz computes a **64-bit SimHash fingerprint** of the stripped HTML body for every response and the base URL baseline. Results with a Hamming distance ≤ 5 bits from the baseline (>92% structural similarity) are suppressed regardless of size difference.

---

## Features

- **6-category false positive engine** — always-on, zero configuration, per-domain adaptive
- **SimHash near-duplicate detection** — catches structurally identical pages that size filters miss
- **Full URL output** — every match prints the complete resolved URL, never truncated
- **Multi-domain fuzzing** (`-targets`) — fuzz multiple targets simultaneously using a shared thread pool
- **WAF bypass** — sends realistic browser headers (`Sec-Fetch-*`, `Accept-Encoding`, `Cache-Control`, `Sec-Ch-Ua`) that bot-detection systems expect
- **Rate-limit handling** — auto-detects 429 / 503 responses and retries with exponential backoff
- **WAF detection** — warns in real time when >80% of responses are 403, with suggested mitigations
- **Auto-calibration** (`-ac`) — additionally filters out generic error pages using random-probe baseline
- **Debug mode** (`-debug`) — prints every request and response header + body preview
- **Rotating User-Agents** — cycles through 5 realistic Chrome / Firefox / Safari UAs
- **Colored output** (`-c`) — status codes, matches, errors, and progress all color-coded
- **Flexible output** — JSON, CSV, Markdown

---

## Install

### Prerequisites

- [Go 1.21+](https://go.dev/dl/)
- Git

### Build

```bash
git clone https://github.com/xhackingz/apifuzz.git
cd apifuzz
go build -buildvcs=false -o apifuzz .
```

---

## Update

```bash
git pull
go build -buildvcs=false -o apifuzz .
./apifuzz -V
```

---

## Usage

```
./apifuzz -u <URL> [flags]
```

`FUZZ` is the keyword replaced by each word in the wordlist.

### Examples

```bash
# Basic path fuzzing — false positive engine runs automatically
./apifuzz -u https://api.example.com/FUZZ -mc 200 -c

# With custom wordlist and colored output
./apifuzz -u https://api.example.com/FUZZ -w ./wordlists/ultimate_fuzz_master.txt -mc 200 -c

# Against a WAF-protected target (slow + realistic)
./apifuzz -u https://api.example.com/FUZZ -t 5 -p 1.0-2.0 -retries 3 -mc 200 -c \
  -H 'Authorization: Bearer YOUR_TOKEN'

# Debug mode — see every request and response
./apifuzz -u https://api.example.com/FUZZ -t 1 -mc 200 -debug

# Verbose — see what is filtered and why
./apifuzz -u https://api.example.com/FUZZ -mc 200 -v -c

# Auto-calibrate (random-probe baseline, in addition to the built-in engine)
./apifuzz -u https://api.example.com/FUZZ -ac -mc 200 -c

# POST body fuzzing
./apifuzz -u https://api.example.com/login -X POST -d 'user=admin&pass=FUZZ' -mc 200

# Save results to JSON
./apifuzz -u https://api.example.com/FUZZ -mc 200 -o results.json -of json
```

---

## Multi-Domain Fuzzing

Use `-targets` to fuzz multiple API domains at the same time. All targets share a single thread pool — no performance loss, no sequential queuing.

The false positive engine runs **per-domain independently** in multi-target mode. Each domain gets its own baseline fingerprint, SimHash anchor, redirect sink counter, and CDN hit tracker. One domain's catch-all page does not pollute another domain's results.

### 1. Create a targets file

List one URL per line. Blank lines and lines starting with `#` are ignored.

**You do not need to add `FUZZ` manually.** If a line doesn't contain `FUZZ`, the tool automatically appends `/FUZZ` to it. Both formats work:

```
# targets.txt — plain base URLs (FUZZ appended automatically)
https://api1.example.com
https://api2.example.com
https://api3.example.com
```

```
# targets.txt — explicit FUZZ placement (use this to fuzz a specific path)
https://api1.example.com/v2/FUZZ
https://api2.example.com/api/FUZZ
https://api3.example.com/FUZZ
```

You can mix both styles in the same file.

### 2. Run with `-targets`

```bash
./apifuzz -targets targets.txt -mc 200 -c
```

That's it. With the default `-t 40`, all three domains are fuzzed concurrently from the very first request.

### How it works

Jobs are interleaved across all targets in round-robin order before being fed into the shared worker pool:

```
word1 → api1.example.com
word1 → api2.example.com
word1 → api3.example.com
word2 → api1.example.com
word2 → api2.example.com
...
```

This means every domain receives traffic simultaneously — increasing `-t` speeds up all domains equally.

### Examples

```bash
# Fuzz 3 domains concurrently with 40 threads (default)
./apifuzz -targets targets.txt -mc 200 -c

# Custom wordlist + higher thread count
./apifuzz -targets targets.txt -w ./wordlists/ultimate_fuzz_master.txt -t 80 -mc 200 -c

# Add auth header applied to all targets
./apifuzz -targets targets.txt -t 40 -mc 200 \
  -H 'Authorization: Bearer YOUR_TOKEN'

# WAF-aware: slow down across all targets uniformly
./apifuzz -targets targets.txt -t 10 -p 0.5-1.5 -retries 2 -mc 200 -c

# Save all results to a JSON file
./apifuzz -targets targets.txt -mc 200 -o results.json -of json
```

### Rules & notes

| | |
|---|---|
| `-u` and `-targets` | Mutually exclusive — use one or the other |
| `FUZZ` keyword | Optional — if a line doesn't contain `FUZZ`, the tool automatically appends `/FUZZ` to it |
| Wordlist | Works exactly the same as single-target mode; use `-w` or rely on the built-in list |
| All other flags | `-mc`, `-fc`, `-ms`, `-H`, `-b`, `-ac`, `-o`, `-debug`, etc. all apply globally to every target |
| Thread count | `-t 40` with 3 domains = all 3 are fuzzed simultaneously, not 40 ÷ 3 per domain |

---

## Flags

| Flag | Description |
|------|-------------|
| `-u` | Target URL — put `FUZZ` where the payload goes |
| `-targets` | File containing multiple target URLs (one per line, each must contain `FUZZ`) |
| `-w` | Wordlist path or URL (uses built-in list if omitted) |
| `-X` | HTTP method (default: `GET`, auto-`POST` if `-d` is set) |
| `-d` | POST / PUT body data |
| `-H` | Header (`"Name: value"`, repeatable) |
| `-b` | Cookie (`"name=value"`, repeatable) |
| `-t` | Threads — concurrent requests (default: `40`) |
| `-rate` | Max requests per second (default: `0` = unlimited) |
| `-p` | Delay between requests in seconds, e.g. `0.5` or `0.5-2.0` range |
| `-timeout` | HTTP timeout in seconds (default: `10`) |
| `-retries` | Retry failed / rate-limited requests N times (default: `0`) |
| `-ac` | Auto-calibrate: filter out baseline noise using random probes (in addition to built-in engine) |
| `-mc` | Match HTTP status codes (default: `200,204,301,302,307,401,403,405`) |
| `-fc` | Filter HTTP status codes |
| `-ms` | Match response size (bytes) |
| `-fs` | Filter response size (bytes) |
| `-mw` | Match word count |
| `-fw` | Filter word count |
| `-ml` | Match line count |
| `-fl` | Filter line count |
| `-mr` | Match regexp |
| `-fr` | Filter regexp |
| `-mt` | Match response time (ms) |
| `-ft` | Filter response time (ms) |
| `-e` | Extensions to append, e.g. `.php,.html` |
| `-o` | Output file path |
| `-of` | Output format: `json` (default), `csv`, `md` |
| `-c` | Colored output |
| `-v` | Verbose — show filtered results with suppression reason |
| `-s` | Silent mode — results only |
| `-debug` | Debug mode — print raw request/response details |
| `-json` | Print results as JSON to stdout |
| `-r` | Follow redirects |
| `-x` | Proxy URL, e.g. `http://127.0.0.1:8080` |
| `-replay-proxy` | Replay matched requests through a second proxy |
| `-maxtime` | Max total run time in seconds |
| `-sf` | Stop when >95% of responses are 403 |
| `-se` | Stop on spurious errors |
| `-sa` | Stop on all error conditions |
| `-V` | Print version |

---

## Tips for WAF-protected targets

When a server returns 403 for everything during fuzzing (even known valid endpoints), the server is likely blocking automated traffic. Try:

```bash
# Reduce threads and add delay
./apifuzz -u https://api.example.com/FUZZ -t 5 -p 1.0-2.0 -retries 3 -mc 200

# Add Authorization header if the API requires authentication
./apifuzz -u https://api.example.com/FUZZ -t 5 -mc 200 \
  -H 'Authorization: Bearer YOUR_TOKEN_HERE'

# Avoid auto-calibration when the server is rate-limiting
# (calibration requests may all return 403, making -ac unreliable)
./apifuzz -u https://api.example.com/FUZZ -t 5 -mc 200 -p 1.0
```

---

## Auto-calibration

The built-in false positive engine (always-on) is complemented by optional auto-calibration (`-ac`). When `-ac` is used, apifuzz sends 5 additional requests with random payloads before scanning. If most responses share the same size, word count, or line count, those values are added as extra filters — layered on top of the six-category engine.

**Note:** If the server is already rate-limiting during calibration (returning 403 to all 5 baseline requests), apifuzz will warn you and suggest disabling `-ac`.

---

## Output format

Each match prints the full resolved URL:

```
URL                                                              Status      Size   Words   Lines   Duration
------------------------------------------------------------------------------------------------------------
https://api.example.com/v1/GuestSession/88e23aa3-015c-...
                                                                    200       1423      56      12     392ms
```

Use `-v` (verbose) to also see filtered results and the reason each was suppressed:

```
[filtered] https://api.example.com/FUZZ → filtered: matches base URL baseline (SPA / soft-redirect / near-duplicate)
[filtered] https://api.example.com/home → filtered: soft-404 phrase detected in response body
[filtered] https://api.example.com/old  → filtered: JavaScript/meta soft-redirect detected in response body
```

---

## License

MIT

---

## Author

**xhacking_z**
- Twitter / X: [x.com/xhacking_z](https://x.com/xhacking_z)
- GitHub: [github.com/xhackingz](https://github.com/xhackingz)
