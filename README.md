# apifuzz

Fast API fuzzing tool. Discovers hidden routes and endpoints by injecting a wordlist into the `FUZZ` keyword in a URL.

> Use only on systems you own or have permission to test.

## Install

```bash
git clone https://github.com/xhackingz/apifuzz.git
cd apifuzz
go build -buildvcs=false -o apifuzz .
```

## Usage

```bash
./apifuzz -u https://example.com/api/FUZZ [options]
```

Multiple targets:

```bash
./apifuzz -targets targets.txt [options]
```

## Common Flags

| Flag | Description |
|------|-------------|
| `-u` | Target URL with `FUZZ` keyword |
| `-targets` | File with multiple target URLs |
| `-w` | Wordlist file or URL (built-in default if omitted) |
| `-mc` | Match status codes e.g. `-mc 200,403` |
| `-fc` | Filter status codes e.g. `-fc 404` |
| `-fs` | Filter by response size |
| `-t` | Threads (default: 40) |
| `-rate` | Max requests/sec |
| `-p` | Delay between requests e.g. `0.5` or `0.5-2.0` |
| `-H` | Add header (repeatable) |
| `-b` | Add cookie (repeatable) |
| `-X` | HTTP method |
| `-d` | POST body data, supports `FUZZ` |
| `-r` | Follow redirects |
| `-x` | Proxy URL |
| `-ac` | Auto-calibrate noise filters |
| `-c` | Colorize output |
| `-v` | Verbose (show filtered results) |
| `-o` | Output mode: `normal`, `live`, `silent` |
| `-output` | Save results to file |
| `-of` | File format: `json`, `csv`, `md` |
| `-V` | Show version |

## Examples

```bash
# Basic
./apifuzz -u https://example.com/api/FUZZ -mc 200 -c

# POST fuzzing
./apifuzz -u https://example.com/login -X POST -d 'user=admin&pass=FUZZ' -mc 200

# Live mode (single-line spinner)
./apifuzz -u https://example.com/FUZZ -o live

# Save results
./apifuzz -u https://example.com/FUZZ -o silent -output out.json -of json

# Slow scan with proxy
./apifuzz -u https://example.com/FUZZ -t 5 -p 1.0-2.0 -x http://127.0.0.1:8080
```

## Update

If a new version is pushed to GitHub, pull and rebuild from inside the `apifuzz` folder:

```bash
cd apifuzz
git pull origin master
go build -buildvcs=false -o apifuzz .
./apifuzz -V
```

## Author

**xhacking_z** — [x.com/xhacking_z](https://x.com/xhacking_z)

## License

MIT
