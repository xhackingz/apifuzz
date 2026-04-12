# apifuzz 🚀

A high-performance, **Smart** API & Web fuzzing tool written in Go. Inspired by the methodology of `ffuf`, but powered by a massive, logic-first wordlist.

**Made by xhacking_z**
**Follow me on X: [x.com/xhacking_z](https://x.com/xhacking_z)**

## Why apifuzz? 🤔
Unlike other tools that flood your screen with useless results, `apifuzz` is designed to be **Smart**. It filters out the noise and shows you only what matters, while using a massive 3.6M+ wordlist ordered by logic and importance.

## Features ✨
- **Smart Filtering**: Shows only `200 OK` by default. No more noise!
- **Custom Match Codes**: Use `-mc` to specify which status codes you want to see (e.g., `-mc 200,301,401`).
- **Logic-First Wordlist**: 3.6M+ entries ordered so that high-impact endpoints (api, admin, config, etc.) are tested first.
- **Fast & Concurrent**: Built with Go's goroutines for maximum speed.
- **Memory Efficient**: Streams massive wordlists directly from disk.
- **Easy Installation**: Supports `go install` for quick setup.

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

```bash
apifuzz -s subdomains.txt -w ultimate_fuzz_master.txt -t 100
```

### Advanced Usage (Like ffuf):
Show only 200, 301, and 401 status codes:
```bash
apifuzz -s subdomains.txt -w ultimate_fuzz_master.txt -mc 200,301,401 -t 100
```

### Options:
- `-s`: Path to the file containing subdomains (one per line). **(Required)**
- `-w`: Path to the wordlist file. **(Required)**
- `-mc`: Match HTTP status codes, separated by commas (default: **200**).
- `-t`: Number of concurrent threads (default: 50).
- `-timeout`: HTTP timeout in seconds (default: 10).
- `-h`: Show help menu and usage instructions.

## Methodology 🧠
1. **Logic First**: We test the most likely endpoints first to get you results faster.
2. **Noise Reduction**: We hide 403/404 by default so you can focus on valid findings.
3. **Massive Coverage**: After the common words, we dive into 3.6M+ entries for deep discovery.

## License 📄
This project is [MIT](LICENSE) licensed.

---
*Created by xhacking_z - Happy Hunting!*
