package filter

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"apifuzz/pkg/ffuf"
)

type valueRange struct {
	min int64
	max int64
}

func parseValueRanges(value string, allowAll bool) ([]valueRange, bool, error) {
	value = strings.TrimSpace(value)
	if allowAll && value == "all" {
		return nil, true, nil
	}

	ranges := []valueRange{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 || strings.TrimSpace(bounds[0]) == "" || strings.TrimSpace(bounds[1]) == "" {
				return nil, false, fmt.Errorf("invalid range: %s", part)
			}
			min, err := strconv.ParseInt(strings.TrimSpace(bounds[0]), 10, 64)
			if err != nil {
				return nil, false, fmt.Errorf("invalid range minimum: %s", bounds[0])
			}
			max, err := strconv.ParseInt(strings.TrimSpace(bounds[1]), 10, 64)
			if err != nil {
				return nil, false, fmt.Errorf("invalid range maximum: %s", bounds[1])
			}
			if min > max {
				return nil, false, fmt.Errorf("invalid range %s: minimum is greater than maximum", part)
			}
			ranges = append(ranges, valueRange{min: min, max: max})
			continue
		}

		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("invalid value: %s", part)
		}
		ranges = append(ranges, valueRange{min: n, max: n})
	}

	return ranges, false, nil
}

func matchesRanges(value int64, ranges []valueRange) bool {
	for _, r := range ranges {
		if value >= r.min && value <= r.max {
			return true
		}
	}
	return false
}

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
	if passed, reason := PassesFilters(conf, res); !passed {
		return false, reason
	}
	return MatchesMatchers(conf, res)
}

func PassesFilters(conf *ffuf.Config, res *ffuf.Result) (bool, string) {
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
	return true, ""
}

func MatchesMatchers(conf *ffuf.Config, res *ffuf.Result) (bool, string) {
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
	value  string
	ranges []valueRange
	all    bool
}

func NewStatusFilter(value string) (*StatusFilter, error) {
	ranges, all, err := parseValueRanges(value, true)
	if err != nil {
		return nil, fmt.Errorf("invalid status code range %q: %w", value, err)
	}
	return &StatusFilter{value: value, ranges: ranges, all: all}, nil
}

func (f *StatusFilter) Filter(res *ffuf.Result) (bool, error) {
	if f.all {
		return true, nil
	}
	return matchesRanges(res.StatusCode, f.ranges), nil
}

func (f *StatusFilter) Repr() string        { return f.value }
func (f *StatusFilter) ReprVerbose() string { return "Response status: " + f.value }

// ─── Size Filter ─────────────────────────────────────────────────────────────

type SizeFilter struct {
	value  string
	ranges []valueRange
}

func NewSizeFilter(value string) (*SizeFilter, error) {
	ranges, _, err := parseValueRanges(value, false)
	if err != nil {
		return nil, fmt.Errorf("invalid size range %q: %w", value, err)
	}
	return &SizeFilter{value: value, ranges: ranges}, nil
}

func (f *SizeFilter) Filter(res *ffuf.Result) (bool, error) {
	return matchesRanges(res.ContentLength, f.ranges), nil
}

func (f *SizeFilter) Repr() string        { return f.value }
func (f *SizeFilter) ReprVerbose() string { return "Response size: " + f.value }

// ─── Word Filter ─────────────────────────────────────────────────────────────

type WordFilter struct {
	value  string
	ranges []valueRange
}

func NewWordFilter(value string) (*WordFilter, error) {
	ranges, _, err := parseValueRanges(value, false)
	if err != nil {
		return nil, fmt.Errorf("invalid word range %q: %w", value, err)
	}
	return &WordFilter{value: value, ranges: ranges}, nil
}

func (f *WordFilter) Filter(res *ffuf.Result) (bool, error) {
	return matchesRanges(res.ContentWords, f.ranges), nil
}

func (f *WordFilter) Repr() string        { return f.value }
func (f *WordFilter) ReprVerbose() string { return "Response words: " + f.value }

// ─── Line Filter ─────────────────────────────────────────────────────────────

type LineFilter struct {
	value  string
	ranges []valueRange
}

func NewLineFilter(value string) (*LineFilter, error) {
	ranges, _, err := parseValueRanges(value, false)
	if err != nil {
		return nil, fmt.Errorf("invalid line range %q: %w", value, err)
	}
	return &LineFilter{value: value, ranges: ranges}, nil
}

func (f *LineFilter) Filter(res *ffuf.Result) (bool, error) {
	return matchesRanges(res.ContentLines, f.ranges), nil
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
	return f.re.Match(res.Data), nil
}

func (f *RegexpFilter) Repr() string        { return f.value }
func (f *RegexpFilter) ReprVerbose() string { return "Regexp: " + f.value }

// ─── Time Filter ─────────────────────────────────────────────────────────────

type TimeFilter struct {
	value  string
	ranges []valueRange
}

func NewTimeFilter(value string) (*TimeFilter, error) {
	ranges, _, err := parseValueRanges(value, false)
	if err != nil {
		return nil, fmt.Errorf("invalid time range %q: %w", value, err)
	}
	return &TimeFilter{value: value, ranges: ranges}, nil
}

func (f *TimeFilter) Filter(res *ffuf.Result) (bool, error) {
	return matchesRanges(res.Duration.Milliseconds(), f.ranges), nil
}

func (f *TimeFilter) Repr() string        { return f.value + "ms" }
func (f *TimeFilter) ReprVerbose() string { return "Response time: " + f.value + "ms" }
