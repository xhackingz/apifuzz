# apifuzz 🚀

A high-performance, concurrent API & Web fuzzing tool written in Go, designed for bug bounty hunters and security researchers. Optimized for speed and massive wordlist handling.

**Made by xhacking_z**
**Follow me on X: [x.com/xhacking_z](https://x.com/xhacking_z)**

## Features ✨
- **Fast & Concurrent**: Built with Go's goroutines for high-speed fuzzing.
- **Ultimate Wordlist**: Includes a massive master wordlist of over **3.6 million unique entries** aggregated from top-tier sources.
- **Smart Filtering**: Automatically highlights interesting status codes (200, 401, 403, 301, 302, 500).
- **Memory Efficient**: Streams wordlists directly from disk to handle millions of entries without high RAM usage.
- **Easy Installation**: Supports `go install` for quick setup.
- **Help Menu**: Built-in help menu with `-h` flag.

## Installation 🛠️

Ensure you have Go installed on your system, then run:

```bash
go install github.com/xhackingz/apifuzz@latest
```

## Usage 🚀

```bash
apifuzz -s subdomains.txt -w wordlists/ultimate_fuzz_master.txt -t 100
```

### Options:
- `-s`: Path to the file containing subdomains (one per line). **(Required)**
- `-w`: Path to the wordlist file. **(Required)**
- `-t`: Number of concurrent threads (default: 50).
- `-timeout`: HTTP timeout in seconds (default: 10).
- `-h`: Show help menu and usage instructions.

## Wordlist Sources 📚
The **Ultimate Fuzz Master** wordlist is a deduplicated aggregation of:
- **Assetnote** (Automated HTTP Archive Directories & API Routes)
- **OneListForAll** (Consolidated high-quality list)
- **SecLists** (Big, Discovery, Web-Content, API)
- **Bo0oM** (Fuzz.txt)
- **Param Miner** (Top parameters)
- **Custom high-impact endpoints** (`/masterdata`, `/info`, `/status`, etc.)

## Methodology 🧠
This tool follows the "Ultimate Fuzzing" approach:
1. **Recon**: Gather all subdomains for your target.
2. **Fuzz**: Use the massive 3.6M+ master wordlist across all subdomains.
3. **Analyze**: Focus on 200 OK for data leaks, 401/403 for potential bypasses, or 500 for potential crashes/bugs.

## Contributing 🤝
Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/xhackingz/apifuzz/issues).

## License 📄
This project is [MIT](LICENSE) licensed.

---
*Created by xhacking_z - Happy Hunting!*
