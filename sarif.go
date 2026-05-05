package comsarif

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

type BuildOptions struct {
	RootURI string
	LockURI string
}

type advisoryFinding struct {
	Advisory Advisory
	Ignored  bool
}

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver     sarifToolComponent   `json:"driver"`
	Extensions []sarifToolComponent `json:"extensions"`
}

type sarifToolComponent struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifInvocation struct {
	WorkingDirectory sarifArtifactLocation `json:"workingDirectory"`
}

type sarifRule struct {
	ID                   string                       `json:"id"`
	Name                 string                       `json:"name"`
	ShortDescription     sarifMessage                 `json:"shortDescription"`
	FullDescription      sarifMessage                 `json:"fullDescription"`
	Help                 sarifMessage                 `json:"help"`
	DefaultConfiguration *sarifReportingConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           sarifRuleProperties          `json:"properties"`
}

type sarifReportingConfiguration struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags             []string     `json:"tags"`
	Precision        string       `json:"precision"`
	Problem          sarifProblem `json:"problem"`
	SecuritySeverity string       `json:"security-severity,omitempty"`
}

type sarifProblem struct {
	Severity string `json:"severity"`
}

type sarifResult struct {
	RuleID              string                   `json:"ruleId"`
	Message             sarifMessage             `json:"message"`
	Locations           []sarifLocation          `json:"locations"`
	PartialFingerprints sarifPartialFingerprints `json:"partialFingerprints"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifPartialFingerprints struct {
	PrimaryLocationLineHash string `json:"primaryLocationLineHash"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

func BuildReport(auditJSON, composerLockJSON []byte, opts BuildOptions) ([]byte, error) {
	auditDoc, err := parseAuditJSON(auditJSON)
	if err != nil {
		return nil, err
	}

	lockIndex, err := parseComposerLock(composerLockJSON, opts.LockURI)
	if err != nil {
		return nil, err
	}

	run, err := buildRun(auditDoc, lockIndex, opts)
	if err != nil {
		return nil, err
	}

	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return nil, fmt.Errorf("marshal SARIF report: %w", err)
	}

	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

func buildRun(auditDoc AuditDocument, lockIndex composerLockIndex, opts BuildOptions) (sarifRun, error) {
	run := newSARIFRun(opts.RootURI)

	if err := appendAdvisoryFindings(&run, lockIndex, flattenAdvisories(auditDoc.Advisories, false)); err != nil {
		return sarifRun{}, err
	}
	if err := appendAdvisoryFindings(&run, lockIndex, flattenAdvisories(auditDoc.IgnoredAdvisories, true)); err != nil {
		return sarifRun{}, err
	}
	if err := appendAbandonedFindings(&run, lockIndex, auditDoc.Abandoned); err != nil {
		return sarifRun{}, err
	}

	return run, nil
}

func newSARIFRun(rootURI string) sarifRun {
	return sarifRun{
		Tool: sarifTool{
			Driver: sarifToolComponent{
				Name:  "composer",
				Rules: []sarifRule{},
			},
			Extensions: []sarifToolComponent{{
				Name:  "comsarif",
				Rules: []sarifRule{},
			}},
		},
		Invocations: []sarifInvocation{{
			WorkingDirectory: sarifArtifactLocation{URI: rootURI},
		}},
		Results: []sarifResult{},
	}
}

func appendAdvisoryFindings(run *sarifRun, lockIndex composerLockIndex, findings []advisoryFinding) error {
	for _, finding := range findings {
		loc, err := advisoryLocation(lockIndex, finding.Advisory.PackageName)
		if err != nil {
			return err
		}

		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, buildAdvisoryRule(finding))
		result, err := buildAdvisoryResult(finding, loc)
		if err != nil {
			return err
		}
		run.Results = append(run.Results, result)
	}

	return nil
}

func appendAbandonedFindings(run *sarifRun, lockIndex composerLockIndex, abandoned map[string]string) error {
	if len(abandoned) == 0 {
		return nil
	}

	run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, buildAbandonedRule())
	for _, packageName := range sortedKeys(abandoned) {
		loc, err := advisoryLocation(lockIndex, packageName)
		if err != nil {
			return err
		}
		run.Results = append(run.Results, buildAbandonedResult(packageName, abandoned[packageName], loc))
	}

	return nil
}

func advisoryLocation(lockIndex composerLockIndex, packageName string) (lockedPackageLocation, error) {
	loc, ok := lockIndex[packageName]
	if !ok {
		return lockedPackageLocation{}, fmt.Errorf("package %q not found in composer.lock", packageName)
	}
	return loc, nil
}

func flattenAdvisories(groups map[string][]Advisory, ignored bool) []advisoryFinding {
	findings := make([]advisoryFinding, 0)
	for _, packageName := range sortedKeys(groups) {
		for _, advisory := range groups[packageName] {
			findings = append(findings, advisoryFinding{Advisory: advisory, Ignored: ignored})
		}
	}
	return findings
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func buildAdvisoryRule(finding advisoryFinding) sarifRule {
	fallback := advisoryDescriptorValue(finding.Advisory)
	problemSeverity := "error"
	if finding.Ignored {
		problemSeverity = "warning"
	}

	rule := sarifRule{
		ID:   hashStable("advisory", finding.Advisory.AdvisoryID, finding.Advisory.PackageName),
		Name: truncateRunes(fallback, 255),
		ShortDescription: sarifMessage{
			Text: truncateRunes(advisoryRuleDescription(finding.Advisory), 1024),
		},
		FullDescription: sarifMessage{
			Text: truncateRunes(advisoryRuleDescription(finding.Advisory), 1024),
		},
		Help: sarifMessage{Text: "Upgrade to patched versions or remove the package."},
		Properties: sarifRuleProperties{
			Tags:      []string{"composer", "dependency", "security"},
			Precision: "very-high",
			Problem: sarifProblem{
				Severity: problemSeverity,
			},
		},
	}

	if securitySeverity, ok := securitySeverityFor(finding.Advisory.Severity); ok {
		rule.Properties.SecuritySeverity = securitySeverity
	}

	return rule
}

func buildAdvisoryResult(finding advisoryFinding, loc lockedPackageLocation) (sarifResult, error) {
	if loc.PackageName != finding.Advisory.PackageName {
		return sarifResult{}, fmt.Errorf("location package %q does not match advisory package %q", loc.PackageName, finding.Advisory.PackageName)
	}

	return sarifResult{
		RuleID:  hashStable("advisory", finding.Advisory.AdvisoryID, finding.Advisory.PackageName),
		Message: sarifMessage{Text: formatAdvisoryMessage(finding)},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: loc.URI},
				Region: sarifRegion{
					StartLine:   loc.Region.StartLine,
					StartColumn: loc.Region.StartColumn,
					EndLine:     loc.Region.EndLine,
					EndColumn:   loc.Region.EndColumn,
				},
			},
		}},
		PartialFingerprints: sarifPartialFingerprints{
			PrimaryLocationLineHash: hashStable(finding.Advisory.AdvisoryID, finding.Advisory.PackageName),
		},
	}, nil
}

func buildAbandonedRule() sarifRule {
	return sarifRule{
		ID:   "abandoned",
		Name: "Composer audit (abandoned)",
		ShortDescription: sarifMessage{
			Text: "Abandoned Composer package",
		},
		FullDescription: sarifMessage{
			Text: "Abandoned Composer package installed.",
		},
		DefaultConfiguration: &sarifReportingConfiguration{Level: "note"},
		Help:                 sarifMessage{Text: "Remove the package."},
		Properties: sarifRuleProperties{
			Tags:      []string{"composer", "dependency"},
			Precision: "high",
			Problem: sarifProblem{
				Severity: "warning",
			},
		},
	}
}

func buildAbandonedResult(packageName, replacement string, loc lockedPackageLocation) sarifResult {
	message := fmt.Sprintf("Package %s is abandoned, you should avoid using it.\n", packageName)
	if replacement == "" {
		message += "No replacement was suggested."
	} else {
		message += fmt.Sprintf("Use %s instead.", replacement)
	}

	return sarifResult{
		RuleID:  "abandoned",
		Message: sarifMessage{Text: message},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: loc.URI},
				Region: sarifRegion{
					StartLine:   loc.Region.StartLine,
					StartColumn: loc.Region.StartColumn,
					EndLine:     loc.Region.EndLine,
					EndColumn:   loc.Region.EndColumn,
				},
			},
		}},
		PartialFingerprints: sarifPartialFingerprints{
			PrimaryLocationLineHash: hashStable("abandoned", packageName),
		},
	}
}

func truncateRunes(s string, limit int) string {
	if limit <= 0 || s == "" {
		return ""
	}
	if utf8.RuneCountInString(s) <= limit {
		return s
	}

	var b strings.Builder
	b.Grow(min(len(s), limit))
	count := 0
	for _, r := range s {
		if count == limit {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func hashStable(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "$$$")))
	return hex.EncodeToString(h[:])
}

func securitySeverityFor(s string) (string, bool) {
	switch s {
	case "critical":
		return "9.0", true
	case "high":
		return "7.0", true
	case "medium":
		return "4.0", true
	case "low":
		return "0.1", true
	default:
		return "", false
	}
}

func formatAdvisoryMessage(finding advisoryFinding) string {
	lines := []string{
		advisoryMessageSummary(finding.Advisory),
		"",
		"advisoryId: " + finding.Advisory.AdvisoryID,
		"packageName: " + finding.Advisory.PackageName,
		"affectedVersions: " + finding.Advisory.AffectedVersions,
	}

	if finding.Advisory.CVE != "" {
		lines = append(lines, "cve: "+finding.Advisory.CVE)
	}
	if finding.Advisory.Link != "" {
		lines = append(lines, "link: "+finding.Advisory.Link)
	}
	if finding.Advisory.ReportedAt != "" {
		lines = append(lines, "reportedAt: "+finding.Advisory.ReportedAt)
	}
	if finding.Advisory.Severity != "" {
		lines = append(lines, "severity: "+finding.Advisory.Severity)
	}
	if finding.Advisory.IgnoreReason != "" {
		lines = append(lines, "ignoreReason: "+finding.Advisory.IgnoreReason)
	}
	if finding.Advisory.ComposerRepository != "" {
		lines = append(lines, "composerRepository: "+finding.Advisory.ComposerRepository)
	}
	if len(finding.Advisory.Sources) > 0 {
		lines = append(lines, "sources:")
		for _, source := range finding.Advisory.Sources {
			lines = append(lines, "  "+formatAdvisorySource(source))
		}
	}

	return strings.Join(lines, "\n")
}

func formatAdvisorySource(source AdvisorySource) string {
	switch {
	case source.Name != "" && source.RemoteID != "":
		return source.Name + ": " + source.RemoteID
	case source.Name != "":
		return source.Name
	default:
		return source.RemoteID
	}
}

func advisoryMessageSummary(advisory Advisory) string {
	if advisory.Title != "" {
		return advisory.Title
	}
	return advisoryDescriptionText(advisory)
}

func advisoryDescriptionText(advisory Advisory) string {
	return fmt.Sprintf("Package %s is vulnerable to %s.", advisory.PackageName, advisoryDescriptorValue(advisory))
}

func advisoryRuleDescription(advisory Advisory) string {
	if title := firstNonEmptyLine(advisory.Title); title != "" {
		return title
	}
	return advisoryDescriptionText(advisory)
}

func advisoryDescriptorValue(advisory Advisory) string {
	if advisory.CVE != "" {
		return advisory.CVE
	}
	if title := firstNonEmptyLine(advisory.Title); title != "" {
		return title
	}
	return advisory.AdvisoryID
}
