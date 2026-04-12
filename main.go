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
// Version 1.8.0 - Clean & Smart Edition

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
		fmt.Fprintf(os.Stderr, "  apifuzz -u https://example.com -w wordlist.txt -r -depth 3 -X GET,POST\n")
	}

	targetURL := flag.String("u", "", "Single target URL (e.g., https://example.com)")
	subsFile := flag.String("s", "", "File containing subdomains list")
	wordlist := flag.String("w", "", "Wordlist file (required)")
	threads := flag.Int("t", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	matchCodes := flag.String("mc", "200", "Match HTTP status codes, separated by commas (default: 200)")
	methods := flag.String("X", "GET", "HTTP methods to fuzz, separated by commas (e.g., GET,POST,PUT)")
	recursive := flag.Bool("r", false, "Enable recursive fuzzing")
	maxDepth := flag.Int("depth", 2, "Maximum recursion depth (default: 2)")
	showSize := flag.Bool("size", false, "Show response size in output (default: false)")
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
    Version: 1.8.0 (Clean & Smart Edition)
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
	for i, m := range methodList {
		methodList[i] = strings.ToUpper(strings.TrimSpace(m))
	}

	var targets []string
	if *targetURL != "" {
		targets = append(targets, *targetURL)
	} else {
		targets, _ = readLines(*subsFile)
	}

	wordCount, _ := countLines(*wordlist)
	totalToProcess = uint64(len(targets)) * uint64(wordCount) * uint64(len(methodList))

	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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
			// Improved Live Progress: [Done/Total] Percentage% | RPS | Found
			fmt.Printf("\r\033[36m[%s] %s | [%d/%d] %.2f%% | RPS: %.0f | Found: %d\033[0m", 
				spinner[i%len(spinner)], currentDomain, done, totalToProcess, percentage, rps, found)
			i++
			time.Sleep(100 * time.Millisecond)
		}
	}()

	for _, target := range targets {
		if !strings.HasPrefix(target, "http") {
			target = "https://" + target
		}
		target = strings.TrimSuffix(target, "/")
		fuzzTarget(target, *wordlist, *threads, client, mcMap, methodList, *recursive, *maxDepth, 0, *showSize)
	}

	fmt.Printf("\n\033[32m[+] Fuzzing Complete. Total Found: %d\033[0m\n", atomic.LoadUint64(&foundResults))
}

func fuzzTarget(baseURL, wordlistPath string, threads int, client *http.Client, mcMap map[int]bool, methods []string, recursive bool, maxDepth, currentDepth int, showSize bool) {
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
					req, err := http.NewRequest(method, url, nil)
					if err != nil { continue }
					
					resp, err := client.Do(req)
					if err != nil { continue }
					
					// Smart Filtering: Default to 200 OK only, ignore 302 unless explicitly matched
					if mcMap[resp.StatusCode] {
						atomic.AddUint64(&foundResults, 1)
						
						fmt.Print("\r\033[K")
						color := "\033[32m"
						if resp.StatusCode >= 500 { color = "\033[31m" } else if resp.StatusCode >= 400 { color = "\033[33m" } else if resp.StatusCode >= 300 { color = "\033[34m" }
						
						output := fmt.Sprintf("%s[%d]\033[0m - %s - %s", color, resp.StatusCode, method, url)
						if showSize {
							var size int64
							if resp.ContentLength != -1 {
								size = resp.ContentLength
							} else {
								body, _ := io.ReadAll(resp.Body)
								size = int64(len(body))
							}
							output += fmt.Sprintf(" - Size: %d", size)
						}
						fmt.Println(output)

						if resp.StatusCode == 200 && !strings.Contains(url, ".") {
							go tryExtensions(url, client, mcMap, showSize)
						}

						if recursive && (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 200) {
							if !strings.Contains(url[strings.LastIndex(url, "/"):], ".") {
								newTarget := strings.TrimSuffix(url, "/")
								wordCount, _ := countLines(wordlistPath)
								atomic.AddUint64(&totalToProcess, uint64(wordCount)*uint64(len(methods)))
								go fuzzTarget(newTarget, wordlistPath, threads, client, mcMap, methods, recursive, maxDepth, currentDepth+1, showSize)
							}
						}
					}
					resp.Body.Close()
				}
			}
		}()
	}

	wordlistFile, err := os.Open(wordlistPath)
	if err != nil { return }
	defer wordlistFile.Close()

	scanner := bufio.NewScanner(wordlistFile)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") { continue }
		
		// Clean Wordlist Logic: Skip obvious noise
		lowerWord := strings.ToLower(word)
		if strings.Contains(lowerWord, "/css/") || strings.Contains(lowerWord, "/images/") || 
		   strings.Contains(lowerWord, "/fonts/") || strings.HasPrefix(word, "-") || 
		   strings.Contains(word, "..;") || strings.Contains(word, ".png") || 
		   strings.Contains(word, ".jpg") || strings.Contains(word, ".gif") || 
		   strings.Contains(word, ".css") || strings.Contains(word, ".js") {
			atomic.AddUint64(&totalRequestsDone, uint64(len(methods))) // Skip but count as done
			continue
		}
		
		jobs <- fmt.Sprintf("%s/%s", baseURL, strings.TrimPrefix(word, "/"))
	}
	close(jobs)
	wg.Wait()
}

func tryExtensions(url string, client *http.Client, mcMap map[int]bool, showSize bool) {
	exts := []string{".json", ".bak", ".old", ".config", ".env", ".zip"}
	for _, ext := range exts {
		req, err := http.NewRequest("GET", url+ext, nil)
		if err != nil { continue }
		resp, err := client.Do(req)
		if err == nil {
			if mcMap[resp.StatusCode] {
				fmt.Print("\r\033[K")
				output := fmt.Sprintf("\033[35m[EXT]\033[0m [%d] - GET - %s", resp.StatusCode, url+ext)
				if showSize {
					output += fmt.Sprintf(" - Size: %d", resp.ContentLength)
				}
				fmt.Println(output)
			}
			resp.Body.Close()
		}
	}
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil { return nil, err }
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
	file, err := os.Open(path)
	if err != nil { return 0, err }
	defer file.Close()
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() { count++ }
	return count, scanner.Err()
}
