package comsarif

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Advisory struct {
	AdvisoryID         string
	PackageName        string
	AffectedVersions   string
	Title              string
	CVE                string
	Link               string
	ReportedAt         string
	Severity           string
	IgnoreReason       string
	ComposerRepository string
	Sources            []AdvisorySource
}

type AdvisorySource struct {
	Name     string
	RemoteID string
}

type AuditDocument struct {
	Advisories        map[string][]Advisory
	IgnoredAdvisories map[string][]Advisory
	Abandoned         map[string]string
}

type rawAuditDocument struct {
	Advisories        map[string][]rawAdvisory `json:"advisories"`
	IgnoredAdvisories map[string][]rawAdvisory `json:"ignored-advisories"`
	Abandoned         map[string]*string       `json:"abandoned"`
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
	IgnoreReason       *string             `json:"ignoreReason"`
	ComposerRepository *string             `json:"composerRepository"`
	Sources            []rawAdvisorySource `json:"sources"`
}

type rawAdvisorySource struct {
	Name     *string `json:"name"`
	RemoteID *string `json:"remoteId"`
}

func parseAuditJSON(data []byte) (AuditDocument, error) {
	var raw rawAuditDocument
	if err := json.Unmarshal(data, &raw); err != nil {
		return AuditDocument{}, fmt.Errorf("parse audit JSON: %w", err)
	}

	doc := AuditDocument{
		Advisories:        make(map[string][]Advisory, len(raw.Advisories)),
		IgnoredAdvisories: make(map[string][]Advisory, len(raw.IgnoredAdvisories)),
		Abandoned:         make(map[string]string, len(raw.Abandoned)),
	}

	seen := make(map[string]struct{})

	advisories, err := normalizeAdvisoryGroups(raw.Advisories, seen)
	if err != nil {
		return AuditDocument{}, err
	}
	doc.Advisories = advisories

	ignored, err := normalizeAdvisoryGroups(raw.IgnoredAdvisories, seen)
	if err != nil {
		return AuditDocument{}, err
	}
	doc.IgnoredAdvisories = ignored

	for packageName, replacement := range raw.Abandoned {
		doc.Abandoned[packageName] = normalizeOptionalString(replacement)
	}

	return doc, nil
}

func normalizeAdvisoryGroups(groups map[string][]rawAdvisory, seen map[string]struct{}) (map[string][]Advisory, error) {
	if len(groups) == 0 {
		return map[string][]Advisory{}, nil
	}

	normalized := make(map[string][]Advisory, len(groups))
	keys := make([]string, 0, len(groups))
	for packageName := range groups {
		keys = append(keys, packageName)
	}
	sort.Strings(keys)

	for _, packageName := range keys {
		group := groups[packageName]
		items := make([]Advisory, 0, len(group))
		for i, rawAdvisory := range group {
			advisory, err := normalizeAdvisory(packageName, rawAdvisory)
			if err != nil {
				return nil, fmt.Errorf("package %q advisory %d: %w", packageName, i, err)
			}

			identity := advisory.AdvisoryID + "\x00" + advisory.PackageName
			if _, ok := seen[identity]; ok {
				return nil, fmt.Errorf("duplicate advisory identity %q for package %q", advisory.AdvisoryID, advisory.PackageName)
			}
			seen[identity] = struct{}{}

			items = append(items, advisory)
		}
		normalized[packageName] = items
	}

	return normalized, nil
}

func normalizeAdvisory(groupPackageName string, raw rawAdvisory) (Advisory, error) {
	advisoryID, err := requireNormalizedString(raw.AdvisoryID, "advisoryId")
	if err != nil {
		return Advisory{}, err
	}

	packageName, err := requireNormalizedString(raw.PackageName, "packageName")
	if err != nil {
		return Advisory{}, err
	}
	if packageName != groupPackageName {
		return Advisory{}, fmt.Errorf("packageName %q does not match enclosing key %q", packageName, groupPackageName)
	}

	affectedVersions, err := requireNormalizedString(raw.AffectedVersions, "affectedVersions")
	if err != nil {
		return Advisory{}, err
	}

	var sources []AdvisorySource
	for _, rawSource := range raw.Sources {
		source := AdvisorySource{
			Name:     normalizeOptionalString(rawSource.Name),
			RemoteID: normalizeOptionalString(rawSource.RemoteID),
		}
		if source.Name == "" && source.RemoteID == "" {
			continue
		}
		sources = append(sources, source)
	}

	return Advisory{
		AdvisoryID:         advisoryID,
		PackageName:        packageName,
		AffectedVersions:   affectedVersions,
		Title:              normalizeOptionalString(raw.Title),
		CVE:                normalizeOptionalString(raw.CVE),
		Link:               normalizeOptionalString(raw.Link),
		ReportedAt:         normalizeOptionalString(raw.ReportedAt),
		Severity:           strings.ToLower(normalizeOptionalString(raw.Severity)),
		IgnoreReason:       normalizeOptionalString(raw.IgnoreReason),
		ComposerRepository: normalizeOptionalString(raw.ComposerRepository),
		Sources:            sources,
	}, nil
}

func requireNormalizedString(value *string, fieldName string) (string, error) {
	normalized := normalizeOptionalString(value)
	if normalized == "" {
		return "", fmt.Errorf("missing %s", fieldName)
	}
	return normalized, nil
}

func normalizeOptionalString(value *string) string {
	if value == nil {
		return ""
	}

	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return ""
	}

	return trimmed
}
