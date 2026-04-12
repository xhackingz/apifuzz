package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// apifuzz - High Performance Smart Fuzzing Tool
// Made by xhacking_z (https://x.com/xhacking_z)

type Result struct {
	URL        string
	StatusCode int
	Size       int64
}

var (
	totalRequests uint64
	foundResults  uint64
	currentDomain string
)

func main() {
	// Custom usage message for -h
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of apifuzz:\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -u <url> -w <wordlist_file> [options]\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -s <subdomains_file> -w <wordlist_file> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -u https://example.com -w wordlist.txt -t 100\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -s subdomains.txt -w wordlist.txt -mc 200,301 -t 50\n")
	}

	targetURL := flag.String("u", "", "Single target URL (e.g., https://example.com)")
	subsFile := flag.String("s", "", "File containing subdomains list")
	wordlist := flag.String("w", "", "Wordlist file (required)")
	threads := flag.Int("t", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	matchCodes := flag.String("mc", "200", "Match HTTP status codes, separated by commas (default: 200)")
	flag.Parse()

	fmt.Println(`
  _____  _____  ______ _    _ ________ 
 |  __ \|  __ \|  ____| |  | |___  /  |
 | |__) | |__) | |__  | |  | |  / /|  |
 |  ___/|  ___/|  __| | |  | | / / |  |
 | |    | |    | |    | |__| |/ /__|__|
 |_|    |_|    |_|     \____//_____(_)
                                       
    API & Web Fuzzer - Made by xhacking_z
    Follow me: https://x.com/xhacking_z
	`)

	if (*targetURL == "" && *subsFile == "") || *wordlist == "" {
		fmt.Println("Error: You must provide either -u (single target) or -s (subdomains file), and -w (wordlist).")
		flag.Usage()
		os.Exit(1)
	}

	// Parse match codes
	mcMap := make(map[int]bool)
	codes := strings.Split(*matchCodes, ",")
	for _, c := range codes {
		code, err := strconv.Atoi(strings.TrimSpace(c))
		if err == nil {
			mcMap[code] = true
		}
	}

	var targets []string
	if *targetURL != "" {
		targets = append(targets, *targetURL)
	} else {
		var err error
		targets, err = readLines(*subsFile)
		if err != nil {
			fmt.Printf("Error reading subdomains: %v\n", err)
			os.Exit(1)
		}
	}

	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Live Spinner/Counter
	go func() {
		spinner := []string{"|", "/", "-", "\\"}
		i := 0
		for {
			fmt.Printf("\r\033[36m[%s] Target: %s | Requests: %d | Found: %d\033[0m", 
				spinner[i%len(spinner)], currentDomain, atomic.LoadUint64(&totalRequests), atomic.LoadUint64(&foundResults))
			i++
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Process each target sequentially
	for _, target := range targets {
		if !strings.HasPrefix(target, "http") {
			target = "https://" + target
		}
		target = strings.TrimSuffix(target, "/")
		currentDomain = target

		jobs := make(chan string, *threads*2)
		var wg sync.WaitGroup

		// Start workers for the current target
		for i := 0; i < *threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for url := range jobs {
					atomic.AddUint64(&totalRequests, 1)
					resp, err := client.Get(url)
					if err != nil {
						continue
					}
					
					if mcMap[resp.StatusCode] {
						atomic.AddUint64(&foundResults, 1)
						
						var size int64
						if resp.ContentLength != -1 {
							size = resp.ContentLength
						} else {
							body, _ := io.ReadAll(resp.Body)
							size = int64(len(body))
						}

						fmt.Print("\r\033[K")
						color := "\033[32m" // Green for 200
						if resp.StatusCode >= 500 {
							color = "\033[31m" // Red for 500
						} else if resp.StatusCode >= 400 {
							color = "\033[33m" // Yellow for 400s
						} else if resp.StatusCode >= 300 {
							color = "\033[34m" // Blue for 300s
						}
						fmt.Printf("%s[%d]\033[0m - Size: %d - %s\n", color, resp.StatusCode, size, url)
					}
					resp.Body.Close()
				}
			}()
		}

		// Feed wordlist for the current target
		wordlistFile, err := os.Open(*wordlist)
		if err != nil {
			fmt.Printf("\nError opening wordlist: %v\n", err)
			continue
		}
		
		scanner := bufio.NewScanner(wordlistFile)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word == "" || strings.HasPrefix(word, "#") {
				continue
			}
			word = strings.TrimPrefix(word, "/")
			jobs <- fmt.Sprintf("%s/%s", target, word)
		}
		wordlistFile.Close()
		close(jobs)
		wg.Wait()
	}

	fmt.Printf("\n\033[32m[+] Fuzzing Complete. Total Found: %d\033[0m\n", atomic.LoadUint64(&foundResults))
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// Version 1.3.0
