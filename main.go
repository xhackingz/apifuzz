package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL        string
	StatusCode int
	Size       int64
}

func main() {
	subsFile := flag.String("s", "", "File containing subdomains")
	wordlist := flag.String("w", "", "Wordlist file")
	threads := flag.Int("t", 20, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	flag.Parse()

	if *subsFile == "" || *wordlist == "" {
		fmt.Println("Usage: apifuzz -s subdomains.txt -w wordlist.txt [-t 20] [-timeout 10]")
		os.Exit(1)
	}

	subdomains, err := readLines(*subsFile)
	if err != nil {
		fmt.Printf("Error reading subdomains: %v\n", err)
		os.Exit(1)
	}

	words, err := readLines(*wordlist)
	if err != nil {
		fmt.Printf("Error reading wordlist: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	jobs := make(chan string)
	results := make(chan Result)
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
				results <- Result{
					URL:        url,
					StatusCode: resp.StatusCode,
					Size:       resp.ContentLength,
				}
				resp.Body.Close()
			}
		}()
	}

	// Result printer
	go func() {
		for res := range results {
			if res.StatusCode == 200 || res.StatusCode == 401 || res.StatusCode == 403 || res.StatusCode == 301 || res.StatusCode == 302 {
				color := "\033[32m" // Green
				if res.StatusCode >= 400 {
					color = "\033[33m" // Yellow
				} else if res.StatusCode >= 300 {
					color = "\033[34m" // Blue
				}
				fmt.Printf("%s[%d]\033[0m - Size: %d - %s\n", color, res.StatusCode, res.Size, res.URL)
			}
		}
	}()

	// Feed jobs
	for _, sub := range subdomains {
		if !strings.HasPrefix(sub, "http") {
			sub = "https://" + sub
		}
		sub = strings.TrimSuffix(sub, "/")
		for _, word := range words {
			word = strings.TrimPrefix(word, "/")
			jobs <- fmt.Sprintf("%s/%s", sub, word)
		}
	}

	close(jobs)
	wg.Wait()
	close(results)
	time.Sleep(1 * time.Second) // Wait for printer to finish
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
