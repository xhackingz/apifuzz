# apifuzz 🚀

A high-performance, concurrent API fuzzing tool written in Go, designed for bug bounty hunters and security researchers. Inspired by real-world findings and optimized for speed and efficiency.

## Features ✨
- **Fast & Concurrent**: Built with Go's goroutines for high-speed fuzzing.
- **Massive Wordlist**: Includes a master wordlist of over **1 million unique entries** aggregated from top-tier sources.
- **Smart Filtering**: Automatically highlights interesting status codes (200, 401, 403, 301, 302).
- **Easy Installation**: Supports `go install` for quick setup.
- **Customizable**: Control threads, timeouts, and more via CLI flags.

## Installation 🛠️

Ensure you have Go installed on your system, then run:

```bash
go install github.com/MahmoudAyman/apifuzz@latest
```

## Usage 🚀

```bash
apifuzz -s subdomains.txt -w wordlists/api_fuzz_master.txt -t 50
```

### Flags:
- `-s`: Path to the file containing subdomains (one per line).
- `-w`: Path to the wordlist file.
- `-t`: Number of concurrent threads (default: 20).
- `-timeout`: HTTP timeout in seconds (default: 10).

## Wordlist Sources 📚
The master wordlist is a deduplicated aggregation of:
- [0xPugal/fuzz4bounty](https://github.com/0xPugal/fuzz4bounty)
- [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) (API & Raft Medium)
- Custom high-impact endpoints (`/masterdata`, `/info`, `/status`, etc.)

## Methodology 🧠
This tool follows the "Smart Fuzzing" approach:
1. **Recon**: Gather all subdomains for your target.
2. **Fuzz**: Use the massive master wordlist across all subdomains.
3. **Analyze**: Focus on 200 OK for data leaks, or 401/403 for potential bypasses or hidden endpoints.

## Contributing 🤝
Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/MahmoudAyman/apifuzz/issues).

## License 📄
This project is [MIT](LICENSE) licensed.

---
*Created by Mahmoud Ayman - Happy Hunting!*
