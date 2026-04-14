package ffuf

import (
        "context"
        "fmt"
        "strings"
)

type Config struct {
        AutoCalibration bool
        Colors          bool
        Context         context.Context
        Cancel          context.CancelFunc
        Data            string
        Debug           bool
        Delay           string
        Extensions      []string
        DirSearchCompat bool
        FilterMode      string
        Filters         map[string]FilterProvider
        FollowRedirects bool
        Headers         map[string]string
        Http2           bool
        IgnoreBody      bool
        IgnoreComments  bool
        Json            bool
        MatcherMode     string
        Matchers        map[string]FilterProvider
        MaxTime         int
        MaxTimeJob      int
        Method          string
        OutputFile      string
        OutputFormat    string
        OutputMode      string
        ProxyURL        string
        Quiet           bool
        Rate            int64
        Raw             bool
        ReplayProxyURL  string
        Retries         int
        StopOn403       bool
        StopOnAll       bool
        StopOnErrors    bool
        Targets         []string
        Threads         int
        Timeout         int
        Url             string
        Verbose         bool
        Wordlists       []string
}

type ConfigOptions struct {
        General GeneralOptions
        HTTP    HTTPOptions
        Input   InputOptions
        Filter  FilterOptions
        Output  OutputOptions
}

type GeneralOptions struct {
        AutoCalibration bool
        Colors          bool
        Debug           bool
        Delay           string
        Json            bool
        MaxTime         int
        MaxTimeJob      int
        Quiet           bool
        Rate            int64
        Retries         int
        ShowVersion     bool
        StopOn403       bool
        StopOnAll       bool
        StopOnErrors    bool
        Threads         int
        Verbose         bool
}

type HTTPOptions struct {
        Cookies         []string
        Data            string
        FollowRedirects bool
        Headers         []string
        Http2           bool
        IgnoreBody      bool
        Method          string
        ProxyURL        string
        Raw             bool
        ReplayProxyURL  string
        Timeout         int
        URL             string
}

type InputOptions struct {
        DirSearchCompat bool
        Extensions      string
        IgnoreComments  bool
        TargetsFile     string
        Wordlists       []string
}

type FilterOptions struct {
        FilterLines  string
        FilterRegexp string
        FilterSize   string
        FilterStatus string
        FilterTime   string
        FilterWords  string
        MatchLines   string
        MatchRegexp  string
        MatchSize    string
        MatchStatus  string
        MatchTime    string
        MatchWords   string
}

type OutputOptions struct {
        OutputFile          string
        OutputFormat        string
        OutputMode          string
        OutputSkipEmptyFile bool
}

func NewConfigOptions() *ConfigOptions {
        return &ConfigOptions{
                General: GeneralOptions{
                        Threads:    40,
                        Delay:      "",
                        Rate:       0,
                        MaxTime:    0,
                        MaxTimeJob: 0,
                },
                HTTP: HTTPOptions{
                        Method:  "GET",
                        Timeout: 10,
                        Headers: []string{},
                        Cookies: []string{},
                },
                Input: InputOptions{
                        Wordlists: []string{},
                },
                Filter: FilterOptions{
                        MatchStatus: "200,204,301,302,307,401,403,405",
                },
                Output: OutputOptions{
                        OutputFormat: "json",
                        OutputMode:   "normal",
                },
        }
}

func ConfigFromOptions(opts *ConfigOptions, ctx context.Context, cancel context.CancelFunc) (*Config, error) {
        conf := &Config{
                AutoCalibration: opts.General.AutoCalibration,
                Colors:          opts.General.Colors,
                Context:         ctx,
                Cancel:          cancel,
                Data:            opts.HTTP.Data,
                Debug:           opts.General.Debug,
                Delay:           opts.General.Delay,
                DirSearchCompat: opts.Input.DirSearchCompat,
                FilterMode:      "or",
                Filters:         make(map[string]FilterProvider),
                FollowRedirects: opts.HTTP.FollowRedirects,
                Headers:         make(map[string]string),
                Http2:           opts.HTTP.Http2,
                IgnoreBody:      opts.HTTP.IgnoreBody,
                IgnoreComments:  opts.Input.IgnoreComments,
                Json:            opts.General.Json,
                MatcherMode:     "or",
                Matchers:        make(map[string]FilterProvider),
                MaxTime:         opts.General.MaxTime,
                MaxTimeJob:      opts.General.MaxTimeJob,
                Method:          opts.HTTP.Method,
                OutputFile:      opts.Output.OutputFile,
                OutputFormat:    opts.Output.OutputFormat,
                OutputMode:      strings.ToLower(strings.TrimSpace(opts.Output.OutputMode)),
                ProxyURL:        opts.HTTP.ProxyURL,
                Quiet:           opts.General.Quiet,
                Rate:            opts.General.Rate,
                Raw:             opts.HTTP.Raw,
                ReplayProxyURL:  opts.HTTP.ReplayProxyURL,
                Retries:         opts.General.Retries,
                StopOn403:       opts.General.StopOn403,
                StopOnAll:       opts.General.StopOnAll,
                StopOnErrors:    opts.General.StopOnErrors,
                Threads:         opts.General.Threads,
                Timeout:         opts.HTTP.Timeout,
                Url:             opts.HTTP.URL,
                Verbose:         opts.General.Verbose,
                Wordlists:       opts.Input.Wordlists,
        }

        // Auto-set POST when body data is provided and no explicit method given
        if conf.Data != "" && conf.Method == "GET" {
                conf.Method = "POST"
        }

        if conf.OutputMode == "" {
                conf.OutputMode = "normal"
        }
        switch conf.OutputMode {
        case "normal", "live", "silent":
        default:
                return nil, fmt.Errorf("invalid output mode %q — use normal, live, or silent", conf.OutputMode)
        }

        // Parse headers
        for _, h := range opts.HTTP.Headers {
                parts := strings.SplitN(h, ":", 2)
                if len(parts) == 2 {
                        conf.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
                }
        }

        // Parse cookies into a Cookie header
        if len(opts.HTTP.Cookies) > 0 {
                existing := conf.Headers["Cookie"]
                cookieStr := strings.Join(opts.HTTP.Cookies, "; ")
                if existing != "" {
                        cookieStr = existing + "; " + cookieStr
                }
                conf.Headers["Cookie"] = cookieStr
        }

        // Parse extensions
        if opts.Input.Extensions != "" {
                for _, ext := range strings.Split(opts.Input.Extensions, ",") {
                        ext = strings.TrimSpace(ext)
                        if ext != "" {
                                if !strings.HasPrefix(ext, ".") {
                                        ext = "." + ext
                                }
                                conf.Extensions = append(conf.Extensions, ext)
                        }
                }
        }

        // Validate: need either -u or -targets.
        // Note: conf.Targets is populated by main.go AFTER this call, so we must
        // also accept opts.Input.TargetsFile being set as a valid alternative.
        if conf.Url == "" && len(conf.Targets) == 0 && opts.Input.TargetsFile == "" {
                return nil, fmt.Errorf("target URL not set — use -u <URL> or -targets <file>")
        }

        return conf, nil
}
