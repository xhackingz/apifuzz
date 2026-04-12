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

// apifuzz - The Ultimate Smart & Recursive Fuzzer
// Made by xhacking_z (https://x.com/xhacking_z)
// Version 1.7.0 - Final Hunter Edition

type Result struct {
	URL        string
	Method     string
	StatusCode int
	Size       int64
}

var (
	totalRequestsDone uint64
	foundResults      uint64
	currentDomain     string
	totalToProcess    uint64
	processedPaths    sync.Map
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
		fmt.Fprintf(os.Stderr, "  apifuzz -u https://example.com -w wordlist.txt -r -depth 3 -X GET,POST\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -s subdomains.txt -w wordlist.txt -mc 200,301 -t 100\n")
	}

	targetURL := flag.String("u", "", "Single target URL (e.g., https://example.com)")
	subsFile := flag.String("s", "", "File containing subdomains list")
	wordlist := flag.String("w", "", "Wordlist file (required)")
	threads := flag.Int("t", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	matchCodes := flag.String("mc", "200", "Match HTTP status codes, separated by commas (default: 200)")
	methods := flag.String("X", "GET", "HTTP methods to fuzz, separated by commas (e.g., GET,POST,PUT)")
	recursive := flag.Bool("r", false, "Enable recursive fuzzing (fuzz discovered directories)")
	maxDepth := flag.Int("depth", 2, "Maximum recursion depth (default: 2)")
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
    Version: 1.7.0 (Final Hunter Edition)
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
		if err == nil && code != 0 {
			mcMap[code] = true
		}
	}

	// Parse methods
	methodList := strings.Split(*methods, ",")
	for i, m := range methodList {
		methodList[i] = strings.ToUpper(strings.TrimSpace(m))
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

	// Pre-calculate initial total requests
	wordCount, _ := countLines(*wordlist)
	totalToProcess = uint64(len(targets)) * uint64(wordCount) * uint64(len(methodList))

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
			fmt.Printf("\r\033[36m[%s] %s | Progress: %.2f%% | RPS: %.0f | Found: %d\033[0m", 
				spinner[i%len(spinner)], currentDomain, percentage, rps, found)
			i++
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Process each target
	for _, target := range targets {
		if !strings.HasPrefix(target, "http") {
			target = "https://" + target
		}
		target = strings.TrimSuffix(target, "/")
		fuzzTarget(target, *wordlist, *threads, client, mcMap, methodList, *recursive, *maxDepth, 0)
	}

	fmt.Printf("\n\033[32m[+] Fuzzing Complete. Total Found: %d\033[0m\n", atomic.LoadUint64(&foundResults))
}

func fuzzTarget(baseURL, wordlistPath string, threads int, client *http.Client, mcMap map[int]bool, methods []string, recursive bool, maxDepth, currentDepth int) {
	if currentDepth > maxDepth {
		return
	}

	// Avoid re-processing the same path
	if _, loaded := processedPaths.LoadOrStore(baseURL, true); loaded {
		return
	}

	currentDomain = baseURL
	jobs := make(chan string, threads*2)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				for _, method := range methods {
					atomic.AddUint64(&totalRequestsDone, 1)
					req, _ := http.NewRequest(method, url, nil)
					resp, err := client.Do(req)
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
						fmt.Printf("%s[%d]\033[0m - %s - Size: %d - %s\n", color, resp.StatusCode, method, size, url)

						// Smart Logic: If we find something interesting, try common sensitive extensions
						if resp.StatusCode == 200 && !strings.Contains(url, ".") {
							go tryExtensions(url, client, mcMap)
						}

						// If recursive is enabled and it's a directory
						if recursive && (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 200) {
							if !strings.Contains(url[strings.LastIndex(url, "/"):], ".") {
								newTarget := strings.TrimSuffix(url, "/")
								wordCount, _ := countLines(wordlistPath)
								atomic.AddUint64(&totalToProcess, uint64(wordCount)*uint64(len(methods)))
								go fuzzTarget(newTarget, wordlistPath, threads, client, mcMap, methods, recursive, maxDepth, currentDepth+1)
							}
						}
					}
					resp.Body.Close()
				}
			}
		}()
	}

	// Feed wordlist
	wordlistFile, err := os.Open(wordlistPath)
	if err != nil {
		return
	}
	defer wordlistFile.Close()

	scanner := bufio.NewScanner(wordlistFile)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		word = strings.TrimPrefix(word, "/")
		jobs <- fmt.Sprintf("%s/%s", baseURL, word)
	}
	close(jobs)
	wg.Wait()
}

func tryExtensions(url string, client *http.Client, mcMap map[int]bool) {
	exts := []string{".json", ".bak", ".old", ".config", ".env", ".zip"}
	for _, ext := range exts {
		req, _ := http.NewRequest("GET", url+ext, nil)
		resp, err := client.Do(req)
		if err == nil {
			if mcMap[resp.StatusCode] {
				fmt.Print("\r\033[K")
				fmt.Printf("\033[35m[EXT]\033[0m [%d] - GET - %s\n", resp.StatusCode, url+ext)
			}
			resp.Body.Close()
		}
	}
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

// Version 1.7.0
