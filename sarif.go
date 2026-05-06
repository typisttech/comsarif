package comsarif

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

func NewReport(auditJSON, composerLockJSON io.Reader, rootURI, lockURI string) (*sarif.Report, error) {
	aud, err := newAudit(auditJSON)
	if err != nil {
		return nil, fmt.Errorf("generate new report: %v", err)
	}

	regs, err := newRegions(composerLockJSON)
	if err != nil {
		return nil, fmt.Errorf("generate new report: %v", err)
	}

	aLoc := sarif.NewSimpleArtifactLocation(lockURI)

	rules, results, err := build(aud, regs, aLoc)
	if err != nil {
		return nil, fmt.Errorf("generate new report: %v", err)
	}

	inv := sarif.NewInvocation().
		WithWorkingDirectory(sarif.NewSimpleArtifactLocation(rootURI)).
		WithExecutionSuccessful(true)

	run := sarif.NewRunWithInformationURI("composer", "https://getcomposer.org/doc/03-cli.md#audit").
		AddInvocation(inv).
		WithResults(results)
	run.Tool.Driver.WithRules(rules)

	report := sarif.NewReport().
		AddRun(run)

	if err := report.Validate(); err != nil {
		return nil, fmt.Errorf("generate new report: %v", err)
	}

	return report, nil
}

func build(aud audit, regs regions, aLoc *sarif.ArtifactLocation) ([]*sarif.ReportingDescriptor, []*sarif.Result, error) {
	rules := make([]*sarif.ReportingDescriptor, 0, len(aud.advisories)+1)
	results := make([]*sarif.Result, 0, len(aud.advisories)+len(aud.abandonments))

	advRules, advResults, err := advisoryFindings(regs, aLoc, aud.advisories...)
	if err != nil {
		return nil, nil, err
	}
	rules = append(rules, advRules...)
	results = append(results, advResults...)

	abRule, abResults, err := abandonedFindings(regs, aLoc, aud.abandonments)
	if err != nil {
		return nil, nil, err
	}
	rules = append(rules, abRule)
	results = append(results, abResults...)

	return rules, results, nil
}

func advisoryFindings(regions regions, aLoc *sarif.ArtifactLocation, advisories ...advisory) ([]*sarif.ReportingDescriptor, []*sarif.Result, error) {
	rules := make([]*sarif.ReportingDescriptor, 0, len(advisories))
	results := make([]*sarif.Result, 0, len(advisories))

	pb := sarif.NewPropertyBag().
		WithTags([]string{"dependency", "security"}).
		Add("precision", "very-high")

	for _, adv := range advisories {
		reg, ok := regions[adv.packageName]
		if !ok {
			return nil, nil, fmt.Errorf("package %q not found in composer.lock", adv.packageName)
		}

		ss := adv.securitySeverity()
		if ss != "" {
			pb.Add("security-severity", ss)
		}

		rule := sarif.NewRule(adv.ruleID()).
			WithDescription(truncate(adv.description(), 1024)).
			WithMarkdownHelp(adv.help()).
			WithProperties(pb)
		rule.WithFullDescription(rule.ShortDescription)
		rules = append(rules, rule)

		result := sarif.NewRuleResult(adv.ruleID()).
			WithMessage(sarif.NewTextMessage(adv.message())).
			AddLocation(newLocation(reg, aLoc)).
			WithPartialFingerprints(map[string]string{
				"primaryLocationLineHash": hashStable("advisory", adv.packageName),
			})
		results = append(results, result)
	}

	return rules, results, nil
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen])
}

func newLocation(region region, aLoc *sarif.ArtifactLocation) *sarif.Location {
	r := sarif.NewSimpleRegion(region.line, region.line).
		WithStartColumn(region.startColumn).
		WithEndColumn(region.endColumn)

	l := sarif.NewPhysicalLocation().
		WithArtifactLocation(aLoc).
		WithRegion(r)

	return sarif.NewLocationWithPhysicalLocation(l)
}

func abandonedFindings(regions regions, aLoc *sarif.ArtifactLocation, abandonments []abandonment) (*sarif.ReportingDescriptor, []*sarif.Result, error) {
	pb := sarif.NewPropertyBag().
		AddTag("dependency").
		Add("precision", "very-high")
	rule := sarif.NewRule("abandoned").
		WithDescription("Abandoned Composer package").
		WithMarkdownHelp("This package has been abandoned, you should avoid using it.").
		WithProperties(pb)
	rule.WithFullDescription(rule.ShortDescription)

	results := make([]*sarif.Result, 0, len(abandonments))

	for _, ab := range abandonments {
		reg, ok := regions[ab.packageName]
		if !ok {
			return nil, nil, fmt.Errorf("package %q not found in composer.lock", ab.packageName)
		}

		result := sarif.NewRuleResult("abandoned").
			WithMessage(sarif.NewTextMessage(ab.message())).
			AddLocation(newLocation(reg, aLoc)).
			WithPartialFingerprints(map[string]string{
				"primaryLocationLineHash": hashStable("abandoned", ab.packageName),
			})
		results = append(results, result)
	}

	return rule, results, nil
}

func hashStable(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "$$$")))
	return hex.EncodeToString(h[:])
}
