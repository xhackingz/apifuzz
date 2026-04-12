package filter

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"apifuzz/pkg/ffuf"
)

func SetupFilters(opts *ffuf.ConfigOptions, conf *ffuf.Config) error {
	// Add matchers
	if err := addMatcher(conf, "status", opts.Filter.MatchStatus); err != nil {
		return err
	}
	if opts.Filter.MatchSize != "" {
		if err := addMatcher(conf, "size", opts.Filter.MatchSize); err != nil {
			return err
		}
	}
	if opts.Filter.MatchWords != "" {
		if err := addMatcher(conf, "word", opts.Filter.MatchWords); err != nil {
			return err
		}
	}
	if opts.Filter.MatchLines != "" {
		if err := addMatcher(conf, "line", opts.Filter.MatchLines); err != nil {
			return err
		}
	}
	if opts.Filter.MatchRegexp != "" {
		if err := addMatcher(conf, "regexp", opts.Filter.MatchRegexp); err != nil {
			return err
		}
	}
	if opts.Filter.MatchTime != "" {
		if err := addMatcher(conf, "time", opts.Filter.MatchTime); err != nil {
			return err
		}
	}

	// Add filters
	if opts.Filter.FilterStatus != "" {
		if err := addFilter(conf, "status", opts.Filter.FilterStatus); err != nil {
			return err
		}
	}
	if opts.Filter.FilterSize != "" {
		if err := addFilter(conf, "size", opts.Filter.FilterSize); err != nil {
			return err
		}
	}
	if opts.Filter.FilterWords != "" {
		if err := addFilter(conf, "word", opts.Filter.FilterWords); err != nil {
			return err
		}
	}
	if opts.Filter.FilterLines != "" {
		if err := addFilter(conf, "line", opts.Filter.FilterLines); err != nil {
			return err
		}
	}
	if opts.Filter.FilterRegexp != "" {
		if err := addFilter(conf, "regexp", opts.Filter.FilterRegexp); err != nil {
			return err
		}
	}
	if opts.Filter.FilterTime != "" {
		if err := addFilter(conf, "time", opts.Filter.FilterTime); err != nil {
			return err
		}
	}
	return nil
}

func addMatcher(conf *ffuf.Config, name, value string) error {
	f, err := newFilterByName(name, value)
	if err != nil {
		return err
	}
	conf.Matchers[name] = f
	return nil
}

func addFilter(conf *ffuf.Config, name, value string) error {
	f, err := newFilterByName(name, value)
	if err != nil {
		return err
	}
	conf.Filters[name] = f
	return nil
}

func newFilterByName(name, value string) (ffuf.FilterProvider, error) {
	switch name {
	case "status":
		return NewStatusFilter(value)
	case "size":
		return NewSizeFilter(value)
	case "word":
		return NewWordFilter(value)
	case "line":
		return NewLineFilter(value)
	case "regexp":
		return NewRegexpFilter(value)
	case "time":
		return NewTimeFilter(value)
	}
	return nil, fmt.Errorf("unknown filter type: %s", name)
}

// ShouldShow returns true if the result should be shown, false with reason if filtered/not matched.
func ShouldShow(conf *ffuf.Config, res *ffuf.Result) (bool, string) {
	// Apply active filters — if any filter matches, hide the result
	for name, f := range conf.Filters {
		matched, err := f.Filter(res)
		if err != nil {
			continue
		}
		if matched {
			return false, fmt.Sprintf("Filtered by %s: %s", name, f.Repr())
		}
	}

	// Apply matchers — result must satisfy at least one matcher (OR mode)
	if len(conf.Matchers) > 0 {
		anyMatched := false
		for _, m := range conf.Matchers {
			matched, err := m.Filter(res)
			if err != nil {
				continue
			}
			if matched {
				anyMatched = true
				break
			}
		}
		if !anyMatched {
			keys := make([]string, 0, len(conf.Matchers))
			for k := range conf.Matchers {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return false, fmt.Sprintf("No matchers matched (%s)", strings.Join(keys, ", "))
		}
	}

	return true, ""
}

// ─── Status Filter ───────────────────────────────────────────────────────────

type StatusFilter struct {
	value string
	codes []int64
	all   bool
}

func NewStatusFilter(value string) (*StatusFilter, error) {
	f := &StatusFilter{value: value}
	if value == "all" {
		f.all = true
		return f, nil
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid status code: %s", part)
		}
		f.codes = append(f.codes, n)
	}
	return f, nil
}

func (f *StatusFilter) Filter(res *ffuf.Result) (bool, error) {
	if f.all {
		return true, nil
	}
	for _, c := range f.codes {
		if res.StatusCode == c {
			return true, nil
		}
	}
	return false, nil
}

func (f *StatusFilter) Repr() string        { return f.value }
func (f *StatusFilter) ReprVerbose() string { return "Response status: " + f.value }

// ─── Size Filter ─────────────────────────────────────────────────────────────

type SizeFilter struct {
	value string
	sizes []int64
}

func NewSizeFilter(value string) (*SizeFilter, error) {
	f := &SizeFilter{value: value}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid size value: %s", part)
		}
		f.sizes = append(f.sizes, n)
	}
	return f, nil
}

func (f *SizeFilter) Filter(res *ffuf.Result) (bool, error) {
	for _, s := range f.sizes {
		if res.ContentLength == s {
			return true, nil
		}
	}
	return false, nil
}

func (f *SizeFilter) Repr() string        { return f.value }
func (f *SizeFilter) ReprVerbose() string { return "Response size: " + f.value }

// ─── Word Filter ─────────────────────────────────────────────────────────────

type WordFilter struct {
	value string
	words []int64
}

func NewWordFilter(value string) (*WordFilter, error) {
	f := &WordFilter{value: value}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid word count: %s", part)
		}
		f.words = append(f.words, n)
	}
	return f, nil
}

func (f *WordFilter) Filter(res *ffuf.Result) (bool, error) {
	for _, w := range f.words {
		if res.ContentWords == w {
			return true, nil
		}
	}
	return false, nil
}

func (f *WordFilter) Repr() string        { return f.value }
func (f *WordFilter) ReprVerbose() string { return "Response words: " + f.value }

// ─── Line Filter ─────────────────────────────────────────────────────────────

type LineFilter struct {
	value string
	lines []int64
}

func NewLineFilter(value string) (*LineFilter, error) {
	f := &LineFilter{value: value}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid line count: %s", part)
		}
		f.lines = append(f.lines, n)
	}
	return f, nil
}

func (f *LineFilter) Filter(res *ffuf.Result) (bool, error) {
	for _, l := range f.lines {
		if res.ContentLines == l {
			return true, nil
		}
	}
	return false, nil
}

func (f *LineFilter) Repr() string        { return f.value }
func (f *LineFilter) ReprVerbose() string { return "Response lines: " + f.value }

// ─── Regexp Filter ───────────────────────────────────────────────────────────

type RegexpFilter struct {
	value string
	re    *regexp.Regexp
}

func NewRegexpFilter(value string) (*RegexpFilter, error) {
	re, err := regexp.Compile(value)
	if err != nil {
		return nil, fmt.Errorf("invalid regexp %q: %w", value, err)
	}
	return &RegexpFilter{value: value, re: re}, nil
}

func (f *RegexpFilter) Filter(res *ffuf.Result) (bool, error) {
	return f.re.MatchString(res.Url), nil
}

func (f *RegexpFilter) Repr() string        { return f.value }
func (f *RegexpFilter) ReprVerbose() string { return "Regexp: " + f.value }

// ─── Time Filter ─────────────────────────────────────────────────────────────

type TimeFilter struct {
	value string
	ms    int64
}

func NewTimeFilter(value string) (*TimeFilter, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid time value (ms): %s", value)
	}
	return &TimeFilter{value: value, ms: n}, nil
}

func (f *TimeFilter) Filter(res *ffuf.Result) (bool, error) {
	return res.Duration.Milliseconds() >= f.ms, nil
}

func (f *TimeFilter) Repr() string        { return f.value + "ms" }
func (f *TimeFilter) ReprVerbose() string { return "Response time: " + f.value + "ms" }
