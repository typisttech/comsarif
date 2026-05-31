package comsarif

import (
	"fmt"
	"io"
	"math/bits"
	"unicode/utf16"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	lineHashBlockSize = 100
	lineHashMod       = uint64(37)
	lineHashEOF       = uint64(65535)
)

type primaryLocationLineHasher struct {
	window      [lineHashBlockSize]uint64
	lineNumbers [lineHashBlockSize]int
	hashCounts  map[string]int
	lineHashes  map[int]string
	firstMod    uint64
	hashRaw     uint64
	index       int
	lineNumber  int
	lineStart   bool
	prevCR      bool
}

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

	if len(aud.abandonments) > 0 {
		abRule, abResults, err := abandonedFindings(regs, aLoc, aud.abandonments)
		if err != nil {
			return nil, nil, err
		}
		rules = append(rules, abRule)
		results = append(results, abResults...)
	}

	return rules, results, nil
}

func advisoryFindings(regions regions, aLoc *sarif.ArtifactLocation, advisories ...advisory) ([]*sarif.ReportingDescriptor, []*sarif.Result, error) {
	rules := make([]*sarif.ReportingDescriptor, 0, len(advisories))
	results := make([]*sarif.Result, 0, len(advisories))

	for _, adv := range advisories {
		reg, ok := regions[adv.packageName]
		if !ok {
			return nil, nil, fmt.Errorf("package %q not found in composer.lock", adv.packageName)
		}

		pb := sarif.NewPropertyBag().
			WithTags([]string{"dependency", "security"}).
			Add("precision", "very-high")
		if ss := adv.severity.score(); ss != "" {
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
				"primaryLocationLineHash": reg.hash,
			})
		results = append(results, result)
	}

	return rules, results, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
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
				"primaryLocationLineHash": reg.hash,
			})
		results = append(results, result)
	}

	return rule, results, nil
}

func primaryLocationLineHashesByLine(data []byte) map[int]string {
	hasher := newPrimaryLocationLineHasher()

	for _, codeUnit := range utf16.Encode([]rune(string(data))) {
		hasher.processCharacter(uint64(codeUnit))
	}
	hasher.processCharacter(lineHashEOF)

	for i := 0; i < lineHashBlockSize; i++ {
		hasher.flush()
	}

	return hasher.lineHashes
}

func newPrimaryLocationLineHasher() *primaryLocationLineHasher {
	hasher := &primaryLocationLineHasher{
		hashCounts: make(map[string]int),
		lineHashes: make(map[int]string),
		firstMod:   lineHashFirstMod(),
		lineStart:  true,
	}
	for i := range hasher.lineNumbers {
		hasher.lineNumbers[i] = -1
	}
	return hasher
}

func (h *primaryLocationLineHasher) flush() {
	if h.lineNumbers[h.index] != -1 {
		h.outputHash()
	}
	h.updateHash(0)
}

func (h *primaryLocationLineHasher) outputHash() {
	hashValue := fmt.Sprintf("%x", h.hashRaw)
	h.hashCounts[hashValue]++
	h.lineHashes[h.lineNumbers[h.index]] = fmt.Sprintf("%s:%d", hashValue, h.hashCounts[hashValue])
	h.lineNumbers[h.index] = -1
}

func (h *primaryLocationLineHasher) updateHash(current uint64) {
	begin := h.window[h.index]
	h.window[h.index] = current
	h.hashRaw = mulAddSubMod37(h.hashRaw, current, begin, h.firstMod)
	h.index = (h.index + 1) % lineHashBlockSize
}

func (h *primaryLocationLineHasher) processCharacter(current uint64) {
	if h.shouldSkipCharacter(current) {
		h.prevCR = false
		return
	}
	current = h.normalizeCharacter(current)
	if h.lineNumbers[h.index] != -1 {
		h.outputHash()
	}
	if h.lineStart {
		h.lineStart = false
		h.lineNumber++
		h.lineNumbers[h.index] = h.lineNumber
	}
	if current == '\n' {
		h.lineStart = true
	}
	h.updateHash(current)
}

func (h *primaryLocationLineHasher) shouldSkipCharacter(current uint64) bool {
	return current == ' ' || current == '\t' || (h.prevCR && current == '\n')
}

func (h *primaryLocationLineHasher) normalizeCharacter(current uint64) uint64 {
	if current == '\r' {
		h.prevCR = true
		return '\n'
	}
	h.prevCR = false
	return current
}

func lineHashFirstMod() uint64 {
	firstMod := uint64(1)
	for i := 0; i < lineHashBlockSize; i++ {
		firstMod *= lineHashMod
	}
	return firstMod
}

func mulAddSubMod37(hashRaw, current, begin, firstMod uint64) uint64 {
	hi, lo := bits.Mul64(lineHashMod, hashRaw)
	lo, _ = bits.Add64(lo, current, 0)
	productHi, productLo := bits.Mul64(firstMod, begin)
	lo, borrow := bits.Sub64(lo, productLo, 0)
	_, _ = bits.Sub64(hi, productHi, borrow)
	return lo
}
