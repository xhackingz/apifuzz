package input

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type WordlistProvider struct {
	words    []string
	position int
	keyword  string
}

func NewWordlistProvider(source, keyword string, ignoreComments bool) (*WordlistProvider, error) {
	var r io.ReadCloser
	var err error

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		r, err = fetchURL(source)
	} else {
		r, err = os.Open(source)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist %q: %w", source, err)
	}
	defer r.Close()

	words, err := parseWords(r, ignoreComments)
	if err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("wordlist %q is empty", source)
	}

	return &WordlistProvider{words: words, keyword: keyword}, nil
}

func fetchURL(url string) (io.ReadCloser, error) {
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d fetching wordlist from %s", resp.StatusCode, url)
	}
	return resp.Body, nil
}

func parseWords(r io.Reader, ignoreComments bool) ([]string, error) {
	var words []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if ignoreComments && (strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//")) {
			continue
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		words = append(words, line)
	}
	return words, scanner.Err()
}

func (w *WordlistProvider) Total() int    { return len(w.words) }
func (w *WordlistProvider) Keyword() string { return w.keyword }
func (w *WordlistProvider) Words() []string { return w.words }
