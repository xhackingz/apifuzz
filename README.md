# apifuzz 🚀

A high-performance, **Smart & Recursive** API & Web fuzzing tool written in Go. Designed to find deep, hidden endpoints that other tools miss.

**Made by xhacking_z**
**Follow me on X: [x.com/xhacking_z](https://x.com/xhacking_z)**

## Why apifuzz? 🤔
Standard fuzzers only scratch the surface. `apifuzz` is built for **Deep Discovery**. If it finds a directory, it can automatically dive inside and fuzz it recursively, helping you find vulnerabilities hidden deep within API structures (like `/v1/GuestSession/UUID`).

## Features ✨
- **Recursive Fuzzing (-r)**: Automatically fuzzes discovered directories to find deep endpoints.
- **Recursion Depth Control (-depth)**: Control how deep the tool should go (default: 2).
- **Smart Filtering**: Shows only `200 OK` by default. No more noise!
- **Live Progress Tracking**: Real-time feedback on Percentage, RPS, and Findings.
- **Logic-First Wordlist**: 3.6M+ entries ordered by impact (api, admin, config, etc. first).
- **Memory Efficient**: Streams massive wordlists directly from disk.

## Installation 🛠️

Ensure you have Go installed on your system, then run:

```bash
go install github.com/xhackingz/apifuzz@latest
```

## Getting the Wordlist 📚

The **Ultimate Fuzz Master** wordlist (3.6M+ entries) is included in this repository.

### Download directly:
```bash
wget https://raw.githubusercontent.com/xhackingz/apifuzz/master/wordlists/ultimate_fuzz_master.txt -O ultimate_fuzz_master.txt
```

## Usage 🚀

### Deep Recursive Fuzzing (Recommended for APIs):
```bash
apifuzz -u https://target.com -w ultimate_fuzz_master.txt -r -depth 3 -t 100
```

### Single Target:
```bash
apifuzz -u https://example.com -w ultimate_fuzz_master.txt -t 100
```

### Multiple Targets:
```bash
apifuzz -s subdomains.txt -w ultimate_fuzz_master.txt -t 100
```

### Options:
- `-u`: Single target URL.
- `-s`: Path to the file containing subdomains.
- `-w`: Path to the wordlist file. **(Required)**
- `-r`: Enable recursive fuzzing (fuzz discovered directories).
- `-depth`: Maximum recursion depth (default: 2).
- `-mc`: Match HTTP status codes (default: **200**).
- `-t`: Number of concurrent threads (default: 50).
- `-timeout`: HTTP timeout in seconds (default: 10).
- `-h`: Show help menu.

## Methodology 🧠
1. **Surface Fuzzing**: Test the main endpoints.
2. **Deep Dive**: If a directory is found, `apifuzz` enters it and starts a new fuzzing session inside.
3. **Logic First**: High-impact words are tested first at every level.

## License 📄
This project is [MIT](LICENSE) licensed.

---
*Created by xhacking_z - Happy Hunting!*
