# apifuzz

A fast API fuzzing tool for discovering hidden API routes, endpoints, and paths.

`apifuzz` replaces the `FUZZ` keyword in a URL with words from a wordlist, sends requests, and shows the responses that look interesting. It is designed to reduce noisy false positives from catch-all pages, SPA fallback pages, soft redirects, and repeated generic responses.

Use it only on systems you own or have permission to test.

---

## Features

- Fast HTTP fuzzing written in Go
- Simple `FUZZ` keyword syntax
- Built-in default wordlist
- Custom local or remote wordlists
- Single-target and multi-target fuzzing
- Match and filter by status code, size, words, lines, regex, or response time
- Automatic false-positive suppression for common catch-all responses
- Compact catch-all summaries with `seen` counts
- Clean terminal output modes: `normal`, `live`, and `silent`
- JSON, CSV, and Markdown result export
- Headers, cookies, POST data, proxy, retries, delay, and rate-limit controls
- Debug and verbose modes when you need more detail

---

## Installation

### Requirements

- Go 1.21 or newer
- Git

### Build from source

```bash
git clone https://github.com/xhackingz/apifuzz.git
cd apifuzz
go build -buildvcs=false -o apifuzz .
```

Check that it runs:

```bash
./apifuzz -V
```

Optional: move the binary somewhere in your PATH:

```bash
sudo mv apifuzz /usr/local/bin/
apifuzz -V
```

---

## Quick Start

Basic fuzzing:

```bash
./apifuzz -u https://example.com/FUZZ
```

Match only `200 OK` responses:

```bash
./apifuzz -u https://example.com/FUZZ -mc 200
```

Use a custom wordlist:

```bash
./apifuzz -u https://example.com/FUZZ -w ./wordlists/paths.txt
```

Use colored output:

```bash
./apifuzz -u https://example.com/FUZZ -c
```

---

## How `FUZZ` Works

`FUZZ` is the place where each word from the wordlist is inserted.

Example:

```bash
./apifuzz -u https://example.com/api/FUZZ -w words.txt
```

If `words.txt` contains:

```text
users
login
admin
```

The tool will request:

```text
https://example.com/api/users
https://example.com/api/login
https://example.com/api/admin
```

---

## Usage

```bash
./apifuzz -u <URL_WITH_FUZZ> [options]
```

Or for multiple targets:

```bash
./apifuzz -targets targets.txt [options]
```

---

## Common Options

| Option | Description |
|---|---|
| `-u` | Target URL. Use `FUZZ` where the wordlist value should go. |
| `-targets` | File containing multiple target URLs. |
| `-w` | Wordlist file path or URL. Uses the built-in wordlist if omitted. |
| `-mc` | Match status codes. Example: `-mc 200,204,403`. |
| `-fc` | Filter status codes. Example: `-fc 404`. |
| `-ms` | Match response size. |
| `-fs` | Filter response size. |
| `-mw` | Match word count. |
| `-fw` | Filter word count. |
| `-ml` | Match line count. |
| `-fl` | Filter line count. |
| `-mr` | Match regex. |
| `-fr` | Filter regex. |
| `-mt` | Match response time in milliseconds. |
| `-ft` | Filter response time in milliseconds. |
| `-t` | Number of threads. Default: `40`. |
| `-rate` | Maximum requests per second. `0` means unlimited. |
| `-p` | Delay between requests. Example: `0.5` or `0.5-2.0`. |
| `-timeout` | HTTP timeout in seconds. |
| `-retries` | Retry failed or rate-limited requests. |
| `-H` | Add a header. Can be used multiple times. |
| `-b` | Add a cookie. Can be used multiple times. |
| `-X` | HTTP method. Example: `GET`, `POST`, `PUT`. |
| `-d` | Request body data. Supports `FUZZ`. |
| `-r` | Follow redirects during normal fuzzing. |
| `-x` | Proxy URL. |
| `-replay-proxy` | Replay matched requests through another proxy. |
| `-ac` | Run extra auto-calibration before fuzzing. |
| `-e` | Add extensions. Example: `.php,.json,.bak`. |
| `-c` | Enable colored output. |
| `-v` | Verbose mode. Shows filtered results and reasons. |
| `-debug` | Print raw request and response details. |
| `-json` | Print results as JSON to stdout. |
| `-output` | Save results to a file. |
| `-output-file` | Same as `-output`. |
| `-of` | Output file format: `json`, `csv`, or `md`. |
| `-o` | Terminal output mode: `normal`, `live`, or `silent`. |
| `-V` | Show version. |

---

## Output Modes

`apifuzz` supports three terminal output modes.

### Normal mode

Default mode.

Shows the banner, setup information, progress, results, and compact catch-all summaries.

```bash
./apifuzz -u https://example.com/FUZZ -o normal
```

Example output style:

```text
[INFO] Loaded 1200 words from: ./words.txt
[INFO] Baseline detection: 1/1 targets have a catch-all baseline active

URL                                                          Status      Size   Words   Lines  Duration
---------------------------------------------------------------------------------------------------------
https://example.com/api/users                                   200       512      18       6      92ms
[CATCH-ALL] example.com (405 B | seen 5x)
```

### Live mode

Single-line live status mode.

Use this when you want a clean terminal with no multi-line spam.

```bash
./apifuzz -u https://example.com/FUZZ -o live
```

Example output style:

```text
⠋ fuzzing... | req/s: 1200 | hits: 34 | catch-all: 2 | seen suppressed: 5
```

### Silent mode

No terminal logs.

Use this for scripts, automation, or when you only want saved output files.

```bash
./apifuzz -u https://example.com/FUZZ -o silent -output results.json -of json
```

---

## Examples

### Basic path fuzzing

```bash
./apifuzz -u https://example.com/FUZZ
```

### Fuzz an API path

```bash
./apifuzz -u https://example.com/api/FUZZ -mc 200
```

### Use a custom wordlist

```bash
./apifuzz -u https://example.com/FUZZ -w ./wordlists/api.txt -mc 200
```

### Show colored output

```bash
./apifuzz -u https://example.com/FUZZ -c
```

### Use live mode

```bash
./apifuzz -u https://example.com/FUZZ -o live
```

Expected style:

```text
⠙ fuzzing... | req/s: 850 | hits: 12 | catch-all: 1 | seen suppressed: 25
```

### Use silent mode and save JSON

```bash
./apifuzz -u https://example.com/FUZZ -o silent -output results.json -of json
```

### Save results as CSV

```bash
./apifuzz -u https://example.com/FUZZ -output results.csv -of csv
```

### Save results as Markdown

```bash
./apifuzz -u https://example.com/FUZZ -output results.md -of md
```

### Match multiple status codes

```bash
./apifuzz -u https://example.com/FUZZ -mc 200,204,403
```

### Filter noisy 404 responses

```bash
./apifuzz -u https://example.com/FUZZ -fc 404
```

### Filter by response size

```bash
./apifuzz -u https://example.com/FUZZ -fs 405
```

### Add a header

```bash
./apifuzz -u https://example.com/FUZZ -H 'Authorization: Bearer YOUR_TOKEN'
```

### Add cookies

```bash
./apifuzz -u https://example.com/FUZZ -b 'session=YOUR_SESSION_VALUE'
```

### POST body fuzzing

```bash
./apifuzz -u https://example.com/login -X POST -d 'username=admin&password=FUZZ' -mc 200
```

### Use a proxy

```bash
./apifuzz -u https://example.com/FUZZ -x http://127.0.0.1:8080
```

### Slow down requests

```bash
./apifuzz -u https://example.com/FUZZ -t 5 -p 1.0-2.0 -retries 3
```

### Verbose mode

```bash
./apifuzz -u https://example.com/FUZZ -v
```

Use verbose mode when you want to see why results were filtered.

### Debug mode

```bash
./apifuzz -u https://example.com/FUZZ -debug -t 1
```

Use debug mode only when troubleshooting. It prints much more detail.

---

## Multi-Target Fuzzing

Create a file named `targets.txt`:

```text
https://example.com/FUZZ
https://test.com/api/FUZZ
https://sample.local/v1/FUZZ
```

Run:

```bash
./apifuzz -targets targets.txt -mc 200
```

You can also list base URLs without `FUZZ`:

```text
https://example.com
https://test.com
https://sample.local
```

If `FUZZ` is missing, apifuzz automatically adds `/FUZZ`.

Example with live mode:

```bash
./apifuzz -targets targets.txt -o live -mc 200
```

---

## Catch-All Output

Some websites return the same page for many unknown paths. These can create false positives.

apifuzz groups repeated catch-all responses by domain and response size, then prints a compact summary.

Example:

```text
[CATCH-ALL] example.com (405 B | seen 5x)
```

This means:

- `example.com` returned the same style of fallback response
- response size was `405 B`
- this fallback has been `seen 5x`
- repeated noise is being suppressed

---

## Updating / Upgrading

When new changes are pushed to GitHub, update your local copy before rebuilding.

### Standard update

From inside the `apifuzz` folder:

```bash
git pull origin master
go build -buildvcs=false -o apifuzz .
./apifuzz -V
```

This repository currently uses the `master` branch. If your fork or clone uses `main`, replace `master` with `main`:

```bash
git pull origin main
go build -buildvcs=false -o apifuzz .
```

### If your branch already tracks origin/master

You can use:

```bash
git pull
go build -buildvcs=false -o apifuzz .
./apifuzz -V
```

### If `git pull` says there is no tracking branch

Run:

```bash
git branch --set-upstream-to=origin/master master
git pull
go build -buildvcs=false -o apifuzz .
```

Or use the direct command:

```bash
git pull origin master
go build -buildvcs=false -o apifuzz .
```

### If dependencies change

This project currently has no third-party Go dependencies. If that changes later, run:

```bash
go mod tidy
go build -buildvcs=false -o apifuzz .
```

### Important warning

Updating may overwrite local edits if you changed files in the repository.

Before updating, save your custom changes or commit them:

```bash
git status
```

If you only use the tool and do not edit its source code, the standard update commands are usually enough.

---

## Beginner Tips

- Start with `-mc 200` to show only successful responses.
- Use `-o live` for long scans to keep the terminal clean.
- Use `-output results.json -of json` when you want to save results.
- Use `-t 5 -p 1.0-2.0` if the target blocks fast scanning.
- Use `-v` only when you need to understand filtering behavior.
- Use `-debug` only for troubleshooting.

---

## License

MIT

---

## Author

**xhacking_z**

- X / Twitter: https://x.com/xhacking_z
- GitHub: https://github.com/xhackingz
