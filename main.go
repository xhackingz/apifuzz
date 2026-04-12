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
	totalRequestsDone uint64
	foundResults      uint64
	currentDomain     string
	totalToProcess    uint64
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

	// Pre-calculate total requests for progress bar
	wordCount, err := countLines(*wordlist)
	if err != nil {
		fmt.Printf("Error counting wordlist: %v\n", err)
		os.Exit(1)
	}
	totalToProcess = uint64(len(targets)) * uint64(wordCount)

	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Live Spinner/Progress Bar
	startTime := time.Now()
	go func() {
		spinner := []string{"|", "/", "-", "\\"}
		i := 0
		for {
			done := atomic.LoadUint64(&totalRequestsDone)
			found := atomic.LoadUint64(&foundResults)
			
			percentage := 0.0
			if totalToProcess > 0 {
				percentage = float64(done) / float64(totalToProcess) * 100
			}
			
			elapsed := time.Since(startTime).Seconds()
			rps := 0.0
			if elapsed > 0 {
				rps = float64(done) / elapsed
			}

			remaining := int64(totalToProcess) - int64(done)
			if remaining < 0 {
				remaining = 0
			}

			fmt.Printf("\r\033[36m[%s] %s | Progress: %.2f%% | Done: %d | Remaining: %d | RPS: %.0f | Found: %d\033[0m", 
				spinner[i%len(spinner)], currentDomain, percentage, done, remaining, rps, found)
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
					resp, err := client.Get(url)
					atomic.AddUint64(&totalRequestsDone, 1)
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

func countLines(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

// Version 1.4.0
