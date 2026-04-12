# xhacking_z | apifuzz

A fast, smart API fuzzing tool built for real-world targets — handles WAF detection, rate limiting, bot-detection bypass, and full URL output out of the box.

Written in Go by **xhacking_z**.

> Default wordlist: [ultimate_fuzz_master.txt](https://raw.githubusercontent.com/xhackingz/apifuzz/master/wordlists/ultimate_fuzz_master.txt) (239,000+ entries)

---

## Features

- **Full URL output** — every match prints the complete resolved URL, never truncated
- **Multi-domain fuzzing** (`-targets`) — fuzz multiple targets simultaneously using a shared thread pool
- **WAF bypass** — sends realistic browser headers (`Sec-Fetch-*`, `Accept-Encoding`, `Cache-Control`, `Sec-Ch-Ua`) that bot-detection systems expect
- **Rate-limit handling** — auto-detects 429 / 503 responses and retries with exponential backoff
- **WAF detection** — warns in real time when >80% of responses are 403, with suggested mitigations
- **Auto-calibration** (`-ac`) — filters out generic error pages without manual tuning
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
# Basic path fuzzing
./apifuzz -u https://api.example.com/FUZZ -mc 200 -c

# With custom wordlist and colored output
./apifuzz -u https://api.example.com/FUZZ -w ./wordlists/ultimate_fuzz_master.txt -mc 200 -c

# Against a WAF-protected target (slow + realistic)
./apifuzz -u https://api.example.com/FUZZ -t 5 -p 1.0-2.0 -retries 3 -mc 200 -c \
  -H 'Authorization: Bearer YOUR_TOKEN'

# Debug mode — see every request and response
./apifuzz -u https://api.example.com/FUZZ -t 1 -mc 200 -debug

# Auto-calibrate to remove false positives
./apifuzz -u https://api.example.com/FUZZ -ac -mc 200 -c

# POST body fuzzing
./apifuzz -u https://api.example.com/login -X POST -d 'user=admin&pass=FUZZ' -mc 200

# Save results to JSON
./apifuzz -u https://api.example.com/FUZZ -mc 200 -o results.json -of json
```

---

## Multi-Domain Fuzzing

Use `-targets` to fuzz multiple API domains at the same time. All targets share a single thread pool — no performance loss, no sequential queuing.

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
| `-ac` | Auto-calibrate: filter out baseline noise automatically |
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
| `-v` | Verbose — show filtered results dimmed |
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

Before scanning, apifuzz sends 5 requests with random payloads. If most responses share the same size, word count, or line count, those values are automatically added as filters. This removes generic "not found" pages without manual tuning.

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

---

## License

MIT

---

## Author

**xhacking_z**
- Twitter / X: [x.com/xhacking_z](https://x.com/xhacking_z)
- GitHub: [github.com/xhackingz](https://github.com/xhackingz)
