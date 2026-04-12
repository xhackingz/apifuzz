# apifuzz 🚀

The **Ultimate Smart & Recursive Fuzzing Tool** for modern API & Web security research. Version 1.6.1 is the most advanced version, combining deep discovery with intelligent logic.

**Made by xhacking_z**
**Follow me on X: [x.com/xhacking_z](https://x.com/xhacking_z)**

## Why apifuzz? 🤔
`apifuzz` is not just a fuzzer; it's a **Bug Bounty Hunter's Arsenal**. It supports single targets, subdomain lists, recursive discovery, and multi-method fuzzing, all powered by a **3.6M+ Logic-First Wordlist**.

## Features ✨
- **Flexible Targets**:
    - **Single Target (-u)**: Fuzz one URL directly.
    - **Subdomains List (-s)**: Fuzz a list of targets sequentially.
- **Intelligence Update (v1.6.1)**:
    - **Method Fuzzing (-X)**: Fuzz using multiple HTTP methods (GET, POST, PUT, etc.).
    - **Smart Extension Hunting**: Automatically tries sensitive extensions (`.bak`, `.env`, `.json`, `.config`) when an interesting endpoint is found.
- **Recursive Fuzzing (-r)**: Automatically dives into discovered directories to find deep endpoints.
- **Recursion Depth Control (-depth)**: Control how deep the tool should go (default: 2).
- **Live Progress Tracking**: Real-time Percentage, RPS, and Findings counter.
- **Logic-First Wordlist**: 3.6M+ entries ordered by impact (api, admin, config, etc. first).
- **Memory Efficient**: Streams massive wordlists directly from disk.

## Installation 🛠️

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

### 1. Single Target (The "Hunter" Mode):
```bash
apifuzz -u https://target.com -w ultimate_fuzz_master.txt -r -depth 3 -X GET,POST -t 100
```

### 2. Multiple Targets (Subdomains List):
```bash
apifuzz -s subdomains.txt -w ultimate_fuzz_master.txt -t 100
```

### 3. Advanced Filtering (Like ffuf):
Show only 200, 301, and 401 status codes:
```bash
apifuzz -u https://target.com -w ultimate_fuzz_master.txt -mc 200,301,401 -t 100
```

### Options:
- `-u`: Single target URL (e.g., https://example.com).
- `-s`: Path to the file containing subdomains (one per line).
- `-w`: Path to the wordlist file. **(Required)**
- `-X`: HTTP methods to fuzz, separated by commas (default: **GET**).
- `-r`: Enable recursive fuzzing.
- `-depth`: Maximum recursion depth (default: 2).
- `-mc`: Match HTTP status codes (default: **200**).
- `-t`: Number of concurrent threads (default: 50).
- `-timeout`: HTTP timeout in seconds (default: 10).
- `-h`: Show help menu.

## Methodology 🧠
1. **Multi-Method Attack**: We don't just GET; we try POST and PUT to find hidden API actions.
2. **Deep Dive**: Recursive mode ensures we find nested endpoints like `/v1/api/users/config`.
3. **Smart Hunting**: If we find `/config`, we automatically check for `/config.bak` or `/config.json`.

## License 📄
This project is [MIT](LICENSE) licensed.

---
*Created by xhacking_z - Happy Hunting!*
