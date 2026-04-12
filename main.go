package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// apifuzz - High Performance Smart Fuzzing Tool
// Made by xhacking_z (https://x.com/xhacking_z)
// Inspired by ffuf methodology

type Result struct {
	URL        string
	StatusCode int
	Size       int64
}

func main() {
	// Custom usage message for -h
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of apifuzz:\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -s <subdomains_file> -w <wordlist_file> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  apifuzz -s subdomains.txt -w wordlist.txt -mc 200,301,401 -t 100\n")
	}

	subsFile := flag.String("s", "", "File containing subdomains (required)")
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

	if *subsFile == "" || *wordlist == "" {
		fmt.Println("Error: Missing required arguments.")
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

	subdomains, err := readLines(*subsFile)
	if err != nil {
		fmt.Printf("Error reading subdomains: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	jobs := make(chan string, *threads*2)
	results := make(chan Result, *threads*2)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				resp, err := client.Get(url)
				if err != nil {
					continue
				}
				
				if mcMap[resp.StatusCode] {
					results <- Result{
						URL:        url,
						StatusCode: resp.StatusCode,
						Size:       resp.ContentLength,
					}
				}
				resp.Body.Close()
			}
		}()
	}

	// Result printer
	go func() {
		for res := range results {
			color := "\033[32m" // Green for 200
			if res.StatusCode >= 500 {
				color = "\033[31m" // Red for 500
			} else if res.StatusCode >= 400 {
				color = "\033[33m" // Yellow for 400s
			} else if res.StatusCode >= 300 {
				color = "\033[34m" // Blue for 300s
			}
			fmt.Printf("%s[%d]\033[0m - Size: %d - %s\n", color, res.StatusCode, res.Size, res.URL)
		}
	}()

	// Feed jobs from wordlist file directly to save memory
	wordlistFile, err := os.Open(*wordlist)
	if err != nil {
		fmt.Printf("Error opening wordlist: %v\n", err)
		os.Exit(1)
	}
	defer wordlistFile.Close()

	scanner := bufio.NewScanner(wordlistFile)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		word = strings.TrimPrefix(word, "/")

		for _, sub := range subdomains {
			if !strings.HasPrefix(sub, "http") {
				sub = "https://" + sub
			}
			sub = strings.TrimSuffix(sub, "/")
			jobs <- fmt.Sprintf("%s/%s", sub, word)
		}
	}

	close(jobs)
	wg.Wait()
	close(results)
	time.Sleep(1 * time.Second)
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

// Version 1.1.0
