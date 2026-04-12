package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"apifuzz/pkg/ffuf"
	"apifuzz/pkg/filter"
	"apifuzz/pkg/output"
	"apifuzz/pkg/runner"
)

type multiStringFlag []string

func (m *multiStringFlag) String() string        { return "" }
func (m *multiStringFlag) Set(v string) error    { *m = append(*m, v); return nil }

type wordlistFlag []string

func (w *wordlistFlag) String() string { return "" }
func (w *wordlistFlag) Set(v string) error {
	parts := strings.Split(v, ",")
	if len(parts) > 1 {
		*w = append(*w, parts...)
	} else {
		*w = append(*w, v)
	}
	return nil
}

func ParseFlags(opts *ffuf.ConfigOptions) *ffuf.ConfigOptions {
	var headers, cookies multiStringFlag
	var wordlists wordlistFlag

	headers = opts.HTTP.Headers
	cookies = opts.HTTP.Cookies
	wordlists = opts.Input.Wordlists

	flag.BoolVar(&opts.General.Colors,         "c",           opts.General.Colors,          "Colorize output")
	flag.BoolVar(&opts.General.Json,            "json",        opts.General.Json,            "JSON output, print newline-delimited JSON records")
	flag.BoolVar(&opts.General.Quiet,           "s",           opts.General.Quiet,           "Silent mode. Print only results.")
	flag.BoolVar(&opts.General.Verbose,         "v",           opts.General.Verbose,         "Verbose output, full URL and redirect location with results")
	flag.BoolVar(&opts.General.Debug,           "debug",       opts.General.Debug,           "Debug mode: print raw request and response details for every request")
	flag.BoolVar(&opts.General.ShowVersion,     "V",           opts.General.ShowVersion,     "Show version information")
	flag.BoolVar(&opts.General.StopOn403,       "sf",          opts.General.StopOn403,       "Stop when > 95% of responses return 403 Forbidden")
	flag.BoolVar(&opts.General.StopOnErrors,    "se",          opts.General.StopOnErrors,    "Stop on spurious errors")
	flag.BoolVar(&opts.General.StopOnAll,       "sa",          opts.General.StopOnAll,       "Stop on all error cases. Implies -sf and -se.")
	flag.BoolVar(&opts.General.AutoCalibration, "ac",          opts.General.AutoCalibration, "Automatically calibrate filtering options")
	flag.IntVar(&opts.General.MaxTime,          "maxtime",     opts.General.MaxTime,         "Maximum running time in seconds for entire process (0 = unlimited)")
	flag.IntVar(&opts.General.MaxTimeJob,       "maxtime-job", opts.General.MaxTimeJob,      "Maximum running time in seconds for a single fuzzing job (0 = unlimited)")
	flag.IntVar(&opts.General.Retries,          "retries",     opts.General.Retries,         "Number of retries for failed/rate-limited requests (default: 0)")

	flag.StringVar(&opts.HTTP.URL,            "u",           opts.HTTP.URL,           "Target URL")
	flag.StringVar(&opts.HTTP.Method,         "X",           opts.HTTP.Method,        "HTTP method to use (default: GET, or POST if data is set)")
	flag.StringVar(&opts.HTTP.Data,           "d",           opts.HTTP.Data,          "POST data")
	flag.StringVar(&opts.HTTP.ProxyURL,       "x",           opts.HTTP.ProxyURL,      "Proxyurl, ex: http://127.0.0.1:8080")
	flag.StringVar(&opts.HTTP.ReplayProxyURL, "replay-proxy",opts.HTTP.ReplayProxyURL,"Replay matched requests using this proxy")
	flag.BoolVar(&opts.HTTP.FollowRedirects,  "r",           opts.HTTP.FollowRedirects,"Follow redirects")
	flag.BoolVar(&opts.HTTP.IgnoreBody,       "ignore-body", opts.HTTP.IgnoreBody,    "Do not fetch the response content")
	flag.BoolVar(&opts.HTTP.Raw,              "raw",         opts.HTTP.Raw,           "Do not encode URI")
	flag.IntVar(&opts.HTTP.Timeout,           "timeout",     opts.HTTP.Timeout,       "HTTP request timeout in seconds")

	flag.StringVar(&opts.Input.Extensions,    "e",  opts.Input.Extensions,   "Comma-separated list of extensions to apply (e.g. .php,.html)")
	flag.BoolVar(&opts.Input.DirSearchCompat, "D",  opts.Input.DirSearchCompat,"DirSearch wordlist compat mode. Used with -e flag.")
	flag.BoolVar(&opts.Input.IgnoreComments,  "ic", opts.Input.IgnoreComments,"Ignore wordlist comments")

	flag.StringVar(&opts.Filter.MatchStatus,  "mc", opts.Filter.MatchStatus,  "Match HTTP status codes, or 'all' for everything")
	flag.StringVar(&opts.Filter.MatchSize,    "ms", opts.Filter.MatchSize,    "Match response size")
	flag.StringVar(&opts.Filter.MatchWords,   "mw", opts.Filter.MatchWords,   "Match amount of words in response")
	flag.StringVar(&opts.Filter.MatchLines,   "ml", opts.Filter.MatchLines,   "Match amount of lines in response")
	flag.StringVar(&opts.Filter.MatchRegexp,  "mr", opts.Filter.MatchRegexp,  "Match regexp")
	flag.StringVar(&opts.Filter.MatchTime,    "mt", opts.Filter.MatchTime,    "Match how many milliseconds to the first response byte")
	flag.StringVar(&opts.Filter.FilterStatus, "fc", opts.Filter.FilterStatus,  "Filter HTTP status codes from response")
	flag.StringVar(&opts.Filter.FilterSize,   "fs", opts.Filter.FilterSize,   "Filter HTTP response size")
	flag.StringVar(&opts.Filter.FilterWords,  "fw", opts.Filter.FilterWords,  "Filter by amount of words in response")
	flag.StringVar(&opts.Filter.FilterLines,  "fl", opts.Filter.FilterLines,  "Filter by amount of lines in response")
	flag.StringVar(&opts.Filter.FilterRegexp, "fr", opts.Filter.FilterRegexp, "Filter regexp")
	flag.StringVar(&opts.Filter.FilterTime,   "ft", opts.Filter.FilterTime,   "Filter response time in milliseconds")

	flag.StringVar(&opts.Output.OutputFile,   "o",  opts.Output.OutputFile,   "Write output to file")
	flag.StringVar(&opts.Output.OutputFormat, "of", opts.Output.OutputFormat,  "Output file format: json, ejson, html, md, csv, ecsv (default: json)")

	flag.IntVar(&opts.General.Threads,  "t",    opts.General.Threads,  "Number of concurrent threads")
	flag.Int64Var(&opts.General.Rate,   "rate", opts.General.Rate,     "Rate of requests per second (0 = unlimited)")
	flag.StringVar(&opts.General.Delay, "p",    opts.General.Delay,    "Seconds of delay between requests (e.g. 0.1, or range 0.1-2.0)")

	flag.Var(&headers,   "H", "Header, e.g.: 'X-Header: value' (can be specified multiple times)")
	flag.Var(&cookies,   "b", "Cookie, e.g.: 'Cookie: foo=bar' (can be specified multiple times)")
	flag.Var(&wordlists, "w", "Wordlist file path or URL (default: built-in wordlist URL)")

	flag.Parse()

	opts.HTTP.Headers = headers
	opts.HTTP.Cookies = cookies
	opts.Input.Wordlists = wordlists

	return opts
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := ffuf.NewConfigOptions()
	opts = ParseFlags(opts)

	if opts.General.ShowVersion {
		fmt.Printf("apifuzz v%s\n", ffuf.Version)
		os.Exit(0)
	}

	if opts.HTTP.URL == "" {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Required flag not set: -u")
		fmt.Fprintln(os.Stderr, "")
		flag.Usage()
		os.Exit(1)
	}

	conf, err := ffuf.ConfigFromOptions(opts, ctx, cancel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] %s\n", err)
		os.Exit(1)
	}

	if err := filter.SetupFilters(opts, conf); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] %s\n", err)
		os.Exit(1)
	}

	out := output.NewStdoutput(conf)

	if !conf.Quiet {
		out.Banner()
	}

	r := runner.NewSimpleRunner(conf)

	if err := r.Run(out); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] %s\n", err)
		os.Exit(1)
	}
}
