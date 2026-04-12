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

// apifuzz - The Ultimate Smart Fuzzing Tool
// Made by xhacking_z (https://x.com/xhacking_z)
// Version 1.6.0 - Intelligence Update

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
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of apifuzz:\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -u <url> -w <wordlist_file> [options]\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -s <subdomains_file> -w <wordlist_file> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -u https://example.com -w wordlist.txt -r -depth 3 -X POST,PUT\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -s subdomains.txt -w wordlist.txt -mc 200,301,401 -t 100\n")
	}

	targetURL := flag.String("u", "", "Single target URL (e.g., https://example.com)")
	subsFile := flag.String("s", "", "File containing subdomains list")
	wordlist := flag.String("w", "", "Wordlist file (required)")
	threads := flag.Int("t", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	matchCodes := flag.String("mc", "200", "Match HTTP status codes (default: 200)")
	methods := flag.String("X", "GET", "HTTP methods to fuzz, separated by commas (e.g., GET,POST,PUT)")
	recursive := flag.Bool("r", false, "Enable recursive fuzzing")
	maxDepth := flag.Int("depth", 2, "Maximum recursion depth")
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
    Version: 1.6.0 (Intelligence Update)
	`)

	if (*targetURL == "" && *subsFile == "") || *wordlist == "" {
		fmt.Println("Error: Missing required arguments.")
		flag.Usage()
		os.Exit(1)
	}

	mcMap := make(map[int]bool)
	for _, c := range strings.Split(*matchCodes, ",") {
		code, _ := strconv.Atoi(strings.TrimSpace(c))
		if code != 0 { mcMap[code] = true }
	}

	methodList := strings.Split(*methods, ",")
	for i, m := range methodList { methodList[i] = strings.ToUpper(strings.TrimSpace(m)) }

	var targets []string
	if *targetURL != "" { targets = append(targets, *targetURL) } else {
		targets, _ = readLines(*subsFile)
	}

	wordCount, _ := countLines(*wordlist)
	totalToProcess = uint64(len(targets)) * uint64(wordCount) * uint64(len(methodList))

	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	startTime := time.Now()
	go func() {
		spinner := []string{"|", "/", "-", "\\"}
		i := 0
		for {
			done := atomic.LoadUint64(&totalRequestsDone)
			found := atomic.LoadUint64(&foundResults)
			percentage := 0.0
			if totalToProcess > 0 { percentage = float64(done) / float64(totalToProcess) * 100 }
			elapsed := time.Since(startTime).Seconds()
			rps := 0.0
			if elapsed > 0 { rps = float64(done) / elapsed }
			fmt.Printf("\r\033[36m[%s] %s | Progress: %.2f%% | RPS: %.0f | Found: %d\033[0m", 
				spinner[i%len(spinner)], currentDomain, percentage, rps, found)
			i++
			time.Sleep(100 * time.Millisecond)
		}
	}()

	for _, target := range targets {
		if !strings.HasPrefix(target, "http") { target = "https://" + target }
		target = strings.TrimSuffix(target, "/")
		fuzzTarget(target, *wordlist, *threads, client, mcMap, methodList, *recursive, *maxDepth, 0)
	}

	fmt.Printf("\n\033[32m[+] Fuzzing Complete. Total Found: %d\033[0m\n", atomic.LoadUint64(&foundResults))
}

func fuzzTarget(baseURL, wordlistPath string, threads int, client *http.Client, mcMap map[int]bool, methods []string, recursive bool, maxDepth, currentDepth int) {
	if currentDepth > maxDepth { return }
	if _, loaded := processedPaths.LoadOrStore(baseURL, true); loaded { return }

	currentDomain = baseURL
	jobs := make(chan string, threads*2)
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				for _, method := range methods {
					atomic.AddUint64(&totalRequestsDone, 1)
					req, _ := http.NewRequest(method, url, nil)
					resp, err := client.Do(req)
					if err != nil { continue }
					
					if mcMap[resp.StatusCode] {
						atomic.AddUint64(&foundResults, 1)
						var size int64
						if resp.ContentLength != -1 { size = resp.ContentLength } else {
							body, _ := io.ReadAll(resp.Body)
							size = int64(len(body))
						}

						fmt.Print("\r\033[K")
						color := "\033[32m"
						if resp.StatusCode >= 500 { color = "\033[31m" } else if resp.StatusCode >= 400 { color = "\033[33m" } else if resp.StatusCode >= 300 { color = "\033[34m" }
						fmt.Printf("%s[%d]\033[0m - %s - Size: %d - %s\n", color, resp.StatusCode, method, size, url)

						// Smart Logic: If we find something interesting, try common sensitive extensions
						if resp.StatusCode == 200 && !strings.Contains(url, ".") {
							go tryExtensions(url, client, mcMap)
						}

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

	wordlistFile, _ := os.Open(wordlistPath)
	defer wordlistFile.Close()
	scanner := bufio.NewScanner(wordlistFile)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") { continue }
		jobs <- fmt.Sprintf("%s/%s", baseURL, strings.TrimPrefix(word, "/"))
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
	file, _ := os.Open(path)
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { lines = append(lines, line) }
	}
	return lines, scanner.Err()
}

func countLines(path string) (int, error) {
	file, _ := os.Open(path)
	defer file.Close()
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() { count++ }
	return count, scanner.Err()
}
