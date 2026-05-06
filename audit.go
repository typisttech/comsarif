package comsarif

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

type audit struct {
	advisories   []advisory
	abandonments []abandonment
}

func newAudit(r io.Reader) (audit, error) {
	var raw rawAudit
	b, err := io.ReadAll(r)
	if err != nil {
		return audit{}, fmt.Errorf("parse audit JSON: %v", err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return audit{}, fmt.Errorf("parse audit JSON: %v", err)
	}

	var doc audit

	advisories, err := raw.Advisories.normalize()
	if err != nil {
		return audit{}, fmt.Errorf("normalize audit JSON advisories: %v", err)
	}

	ignoredAdvisories, err := raw.IgnoredAdvisories.normalize()
	if err != nil {
		return audit{}, fmt.Errorf("normalize audit JSON ignored-advisories: %v", err)
	}

	//nolint:gocritic
	doc.advisories = append(advisories, ignoredAdvisories...)

	doc.abandonments = raw.Abandoned.normalize()

	return doc, nil
}

type advisory struct {
	id                 string
	packageName        string
	affectedVersions   string
	title              string
	cve                string
	link               string
	reportedAt         string
	severity           advisorySeverity
	composerRepository string
	sources            []advisorySource
}

func (a advisory) help() string {
	var sb strings.Builder

	title := a.title
	if strings.HasPrefix(a.id, "WPSECADV/WF/") {
		title = strings.ReplaceAll(title, "\n### ", "\n\n")
	}
	sb.WriteString(title + "\n")

	sb.WriteString(`
| Field | Value |
| --- | --- |
`)

	sb.WriteString(markdownRow("Advisory ID", a.id))
	sb.WriteString(markdownRow("Package Name", a.packageName))
	sb.WriteString(markdownRow("Affected Versions", a.affectedVersions))

	if a.cve != "" {
		sb.WriteString(markdownRow("CVE", a.cve))
	}
	sev := a.severity.String()
	if sev != "" {
		sb.WriteString(markdownRow("Severity", sev))
	}
	if a.link != "" {
		sb.WriteString(markdownRow("Link", a.link))
	}
	if a.reportedAt != "" {
		sb.WriteString(markdownRow("Reported At", a.reportedAt))
	}
	if a.composerRepository != "" {
		sb.WriteString(markdownRow("Composer Repository", a.composerRepository))
	}
	for _, source := range a.sources {
		sb.WriteString(markdownRow("Source", source.String()))
	}

	return sb.String()
}

func markdownRow(field, value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", "")
	return fmt.Sprintf("| %s | %s |\n", field, value)
}

func (a advisory) ruleID() string {
	return "advisory/" + a.packageName + "/" + a.id
}

func (a advisory) description() string {
	if a.cve != "" {
		return a.cve
	}

	// TODO: Use GHSA ID.

	return a.id
}

func (a advisory) message() string {
	return "Package " + a.packageName + " is vulnerable to " + a.description() + "."
}

func (a advisory) securitySeverity() string {
	return a.severity.score()
}

type advisorySeverity string

const (
	severityCritical advisorySeverity = "critical"
	severityHigh     advisorySeverity = "high"
	severityMedium   advisorySeverity = "medium"
	severityLow      advisorySeverity = "low"
	severityNone     advisorySeverity = "none"
	severityUnknown  advisorySeverity = ""
)

func newAdvisorySeverity(severity string) advisorySeverity {
	severity = strings.ToLower(strings.TrimSpace(severity))

	switch severity {
	case "critical":
		return severityCritical
	case "high":
		return severityHigh
	case "medium":
		return severityMedium
	case "low":
		return severityLow
	case "none":
		return severityNone
	default:
		return severityUnknown
	}
}

func (s advisorySeverity) String() string {
	return string(s)
}

func (s advisorySeverity) score() string {
	switch s {
	case severityCritical:
		return "9.0"
	case severityHigh:
		return "7.0"
	case severityMedium:
		return "4.0"
	case severityLow:
		return "0.1"
	default:
		return ""
	}
}

type advisorySource struct {
	name     string
	remoteID string
}

func (s advisorySource) String() string {
	if s.name == "" {
		return s.remoteID
	}
	return fmt.Sprintf("%s (%s)", s.remoteID, s.name)
}

type abandonment struct {
	packageName string
	replacement string
}

func (a abandonment) message() string {
	var sb strings.Builder

	sb.WriteString("Package ")
	sb.WriteString(a.packageName)
	sb.WriteString(" is abandoned, you should avoid using it.")

	if a.replacement == "" {
		sb.WriteString(" No replacement was suggested.")
	} else {
		sb.WriteString(" Use ")
		sb.WriteString(a.replacement)
		sb.WriteString(" instead.")
	}

	return sb.String()
}

type rawAudit struct {
	Advisories        rawAdvisories   `json:"advisories"`
	IgnoredAdvisories rawAdvisories   `json:"ignored-advisories"`
	Abandoned         rawAbandonments `json:"abandoned"`
}

// rawAdvisories is a custom type that accepts either a JSON object
// mapping package -> []rawAdvisory or an empty array ([]) which will
// be treated as an empty map.
type rawAdvisories map[string][]rawAdvisory

func (as *rawAdvisories) UnmarshalJSON(b []byte) error {
	var m map[string][]rawAdvisory
	if err := unmarshalJSONObjectOrEmptyArray(b, "advisories", &m); err != nil {
		return err
	}
	*as = m
	return nil
}

func (as *rawAdvisories) normalize() ([]advisory, error) {
	if as == nil {
		return nil, nil
	}
	m := *as

	groups := make([][]advisory, 0, len(m))
	for pkg, raws := range m {
		group := make([]advisory, 0, len(raws))
		for i, raw := range raws {
			adv, err := raw.normalize()
			if err != nil {
				return nil, fmt.Errorf("package %q advisories[%d]: %w", pkg, i, err)
			}

			group = append(group, adv)
		}
		groups = append(groups, group)
	}

	return slices.Concat(groups...), nil
}

type rawAdvisory struct {
	AdvisoryID         *string             `json:"advisoryId"`
	PackageName        *string             `json:"packageName"`
	AffectedVersions   *string             `json:"affectedVersions"`
	Title              *string             `json:"title"`
	CVE                *string             `json:"cve"`
	Link               *string             `json:"link"`
	ReportedAt         *string             `json:"reportedAt"`
	Severity           *string             `json:"severity"`
	ComposerRepository *string             `json:"composerRepository"`
	Sources            []rawAdvisorySource `json:"sources"`
}

func (a rawAdvisory) normalize() (advisory, error) {
	id := normalizeString(a.AdvisoryID)
	if id == "" {
		return advisory{}, errors.New("missing advisoryId")
	}

	pkg := normalizeString(a.PackageName)
	if pkg == "" {
		return advisory{}, errors.New("missing packageName")
	}

	avs := normalizeString(a.AffectedVersions)
	if avs == "" {
		return advisory{}, errors.New("missing affectedVersions")
	}

	srcs := make([]advisorySource, 0, len(a.Sources))
	for i := range a.Sources {
		src, err := a.Sources[i].normalize()
		if err != nil {
			continue
		}

		srcs = append(srcs, src)
	}

	return advisory{
		id:                 id,
		packageName:        pkg,
		affectedVersions:   avs,
		title:              normalizeString(a.Title),
		cve:                normalizeString(a.CVE),
		link:               normalizeString(a.Link),
		reportedAt:         normalizeString(a.ReportedAt),
		severity:           newAdvisorySeverity(normalizeString(a.Severity)),
		composerRepository: normalizeString(a.ComposerRepository),
		sources:            srcs,
	}, nil
}

type rawAdvisorySource struct {
	Name     *string `json:"name"`
	RemoteID *string `json:"remoteId"`
}

func (s rawAdvisorySource) normalize() (advisorySource, error) {
	rid := normalizeString(s.RemoteID)
	if rid == "" {
		return advisorySource{}, errors.New("empty advisory ID")
	}

	return advisorySource{
		name:     normalizeString(s.Name),
		remoteID: rid,
	}, nil
}

// rawAbandonments accepts either an object mapping package -> *string or
// an empty array.
type rawAbandonments map[string]*string

func (as *rawAbandonments) UnmarshalJSON(b []byte) error {
	var m map[string]*string
	if err := unmarshalJSONObjectOrEmptyArray(b, "abandoned", &m); err != nil {
		return err
	}
	*as = m
	return nil
}

func (as *rawAbandonments) normalize() []abandonment {
	if as == nil {
		return nil
	}
	m := *as

	norms := make([]abandonment, 0, len(m))
	for pkg, re := range m {
		name := normalizeString(&pkg)
		if name == "" {
			continue
		}

		norms = append(norms, abandonment{
			packageName: name,
			replacement: normalizeString(re),
		})
	}

	return norms
}

func unmarshalJSONObjectOrEmptyArray[T any](b []byte, fieldName string, dst *map[string]T) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil
	}

	switch b[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		if len(arr) != 0 {
			return fmt.Errorf("expected empty array for %s", fieldName)
		}
		*dst = map[string]T{}
		return nil
	case '{':
		return json.Unmarshal(b, dst)
	default:
		return fmt.Errorf("invalid %s JSON", fieldName)
	}
}

func normalizeString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
