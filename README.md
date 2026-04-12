# apifuzz 🚀

The **Ultimate Smart Fuzzing Tool** for modern API & Web security research. Version 1.6.0 introduces the **Intelligence Update**, making it a true hunter, not just a fuzzer.

**Made by xhacking_z**
**Follow me on X: [x.com/xhacking_z](https://x.com/xhacking_z)**

## Why apifuzz? 🤔
Most fuzzers just spray and pray. `apifuzz` is designed with **Logic & Intelligence**. It understands the context, tries different HTTP methods, and automatically hunts for sensitive files based on what it finds.

## Features ✨
- **Intelligence Update (v1.6.0)**:
    - **Method Fuzzing (-X)**: Fuzz using multiple HTTP methods (GET, POST, PUT, DELETE, etc.) to find hidden API functionalities.
    - **Smart Extension Hunting**: Automatically tries sensitive extensions (`.bak`, `.env`, `.json`, `.config`) when an interesting endpoint is found.
- **Recursive Fuzzing (-r)**: Automatically dives into discovered directories.
- **Live Progress Tracking**: Real-time Percentage, RPS, and Findings counter.
- **Logic-First Wordlist**: 3.6M+ entries ordered by impact (api, admin, config, etc. first).
- **Memory Efficient**: Streams massive wordlists directly from disk.

## Installation 🛠️

```bash
go install github.com/xhackingz/apifuzz@latest
```

## Usage 🚀

### The "Hunter" Mode (Recursive + Methods + Smart Discovery):
```bash
apifuzz -u https://target.com -w ultimate_fuzz_master.txt -r -depth 3 -X GET,POST,PUT -t 100
```

### Options:
- `-u`: Single target URL.
- `-s`: Path to the file containing subdomains.
- `-w`: Path to the wordlist file. **(Required)**
- `-X`: HTTP methods to fuzz, separated by commas (default: **GET**).
- `-r`: Enable recursive fuzzing.
- `-depth`: Maximum recursion depth (default: 2).
- `-mc`: Match HTTP status codes (default: **200**).
- `-t`: Number of concurrent threads (default: 50).
- `-h`: Show help menu.

## Methodology 🧠
1. **Multi-Method Attack**: We don't just GET; we try POST and PUT to find hidden API actions.
2. **Deep Dive**: Recursive mode ensures we find nested endpoints like `/v1/api/users/config`.
3. **Smart Hunting**: If we find `/config`, we automatically check for `/config.bak` or `/config.json`.

## License 📄
This project is [MIT](LICENSE) licensed.

---
*Created by xhacking_z - Happy Hunting!*
