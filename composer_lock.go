package comsarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"unicode"
	"unicode/utf8"
)

type composerLockIndex map[string]lockedPackageLocation

type lockedPackageLocation struct {
	PackageName string
	Version     string
	URI         string
	Region      region
}

type region struct {
	StartLine   int
	StartColumn int
	EndLine     int
	EndColumn   int
}

func parseComposerLock(data []byte, lockURI string) (composerLockIndex, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	newlines := newlineOffsets(data)

	if err := expectJSONObjectStart(decoder, "top-level object"); err != nil {
		return nil, fmt.Errorf("parse composer.lock JSON: %w", err)
	}

	index := make(composerLockIndex)
	for decoder.More() {
		key, err := nextObjectKey(decoder, "object key")
		if err != nil {
			return nil, fmt.Errorf("parse composer.lock JSON: %w", err)
		}
		if err := scanTopLevelLockValue(decoder, data, newlines, lockURI, index, key); err != nil {
			return nil, err
		}
	}

	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("parse composer.lock JSON: %w", err)
	}

	return index, nil
}

func scanTopLevelLockValue(decoder *json.Decoder, data []byte, newlines []int, lockURI string, index composerLockIndex, key string) error {
	if key == "packages" || key == "packages-dev" {
		return scanLockedPackageArray(decoder, data, newlines, lockURI, index)
	}
	if err := skipJSONValue(decoder); err != nil {
		return fmt.Errorf("parse composer.lock JSON: %w", err)
	}
	return nil
}

func scanLockedPackageArray(decoder *json.Decoder, data []byte, newlines []int, lockURI string, index composerLockIndex) error {
	if err := expectJSONArrayStart(decoder, "package array"); err != nil {
		return fmt.Errorf("parse composer.lock JSON: %w", err)
	}

	for decoder.More() {
		if err := expectJSONObjectStart(decoder, "package object"); err != nil {
			return fmt.Errorf("parse composer.lock JSON: %w", err)
		}

		loc, err := scanLockedPackageObject(decoder, data, newlines, lockURI)
		if err != nil {
			return err
		}

		if _, ok := index[loc.PackageName]; ok {
			return fmt.Errorf("duplicate top-level package %q in composer.lock", loc.PackageName)
		}
		index[loc.PackageName] = loc
	}

	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("parse composer.lock JSON: %w", err)
	}

	return nil
}

func scanLockedPackageObject(decoder *json.Decoder, data []byte, newlines []int, lockURI string) (lockedPackageLocation, error) {
	state := lockedPackageScanState{}

	for decoder.More() {
		key, err := nextObjectKey(decoder, "package field name")
		if err != nil {
			return lockedPackageLocation{}, fmt.Errorf("parse composer.lock JSON: %w", err)
		}
		if err := state.scanField(decoder, newlines, key); err != nil {
			return lockedPackageLocation{}, err
		}
	}

	if _, err := decoder.Token(); err != nil {
		return lockedPackageLocation{}, fmt.Errorf("parse composer.lock JSON: %w", err)
	}

	if state.name == "" {
		return lockedPackageLocation{}, fmt.Errorf("parse composer.lock JSON: package object missing name")
	}
	if state.version == "" {
		return lockedPackageLocation{}, fmt.Errorf("parse composer.lock JSON: package %q missing version", state.name)
	}
	if state.versionLine == 0 {
		return lockedPackageLocation{}, fmt.Errorf("parse composer.lock JSON: package %q missing version line", state.name)
	}

	return lockedPackageLocation{
		PackageName: state.name,
		Version:     state.version,
		URI:         lockURI,
		Region:      regionForLine(data, newlines, state.versionLine),
	}, nil
}

type lockedPackageScanState struct {
	name        string
	version     string
	versionLine int
}

func (state *lockedPackageScanState) scanField(decoder *json.Decoder, newlines []int, key string) error {
	keyOffset := decoder.InputOffset()

	switch key {
	case "name":
		value, err := requireJSONString(decoder, "name")
		if err != nil {
			return err
		}
		state.name = value
	case "version":
		value, err := requireJSONString(decoder, "version")
		if err != nil {
			return err
		}
		state.version = value
		state.versionLine = lineNumberForOffset(newlines, keyOffset-1)
	default:
		if err := skipJSONValue(decoder); err != nil {
			return fmt.Errorf("parse composer.lock JSON: %w", err)
		}
	}

	return nil
}

func expectJSONObjectStart(decoder *json.Decoder, context string) error {
	return expectDelim(decoder, '{', context)
}

func expectJSONArrayStart(decoder *json.Decoder, context string) error {
	return expectDelim(decoder, '[', context)
}

func expectDelim(decoder *json.Decoder, want json.Delim, context string) error {
	tok, err := decoder.Token()
	if err != nil {
		return err
	}

	delim, ok := tok.(json.Delim)
	if !ok || delim != want {
		return fmt.Errorf("expected %s", context)
	}

	return nil
}

func nextObjectKey(decoder *json.Decoder, context string) (string, error) {
	tok, err := decoder.Token()
	if err != nil {
		return "", err
	}

	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected %s", context)
	}

	return key, nil
}

func requireJSONString(decoder *json.Decoder, fieldName string) (string, error) {
	tok, err := decoder.Token()
	if err != nil {
		return "", fmt.Errorf("parse composer.lock JSON: %w", err)
	}

	value, ok := tok.(string)
	if !ok || value == "" {
		return "", fmt.Errorf("parse composer.lock JSON: expected non-empty string for %s", fieldName)
	}

	return value, nil
}

func skipJSONValue(decoder *json.Decoder) error {
	tok, err := decoder.Token()
	if err != nil {
		return err
	}

	return skipJSONValueFromToken(decoder, tok)
}

func skipJSONValueFromToken(decoder *json.Decoder, tok json.Token) error {
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return nil
	}
}

func newlineOffsets(data []byte) []int {
	offsets := make([]int, 0, bytes.Count(data, []byte{'\n'}))
	for i, b := range data {
		if b == '\n' {
			offsets = append(offsets, i)
		}
	}
	return offsets
}

func lineNumberForOffset(newlines []int, offset int64) int {
	if offset < 0 {
		return 1
	}
	return sort.SearchInts(newlines, int(offset)) + 1
}

func regionForLine(data []byte, newlines []int, line int) region {
	start, end := lineBounds(data, newlines, line)
	lineData := data[start:end]
	if n := len(lineData); n > 0 && lineData[n-1] == '\r' {
		lineData = lineData[:n-1]
	}

	return region{
		StartLine:   line,
		StartColumn: firstNonWhitespaceColumn(lineData),
		EndLine:     line,
		EndColumn:   utf8.RuneCount(lineData) + 1,
	}
}

func lineBounds(data []byte, newlines []int, line int) (int, int) {
	start := 0
	if line <= 1 {
		start = 0
	} else {
		start = newlines[line-2] + 1
	}

	end := len(data)
	if line-1 < len(newlines) {
		end = newlines[line-1]
	}

	return start, end
}

func firstNonWhitespaceColumn(line []byte) int {
	column := 1
	for len(line) > 0 {
		r, size := utf8.DecodeRune(line)
		if !unicode.IsSpace(r) {
			return column
		}
		column++
		line = line[size:]
	}

	return 1
}
