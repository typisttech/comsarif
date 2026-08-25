package comsarif

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"sort"
)

type regions map[string]region

type region struct {
	line        int
	startColumn int
	endColumn   int
	hash        string
}

func newRegions(r io.Reader) (regions, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read composer.lock JSON: %w", err)
	}

	regs, err := parseRegions(data)
	if err != nil {
		return nil, err
	}

	lineHashes := primaryLocationLineHashesByLine(data)
	for pkg, reg := range regs {
		hash, ok := lineHashes[reg.line]
		if !ok {
			return nil, fmt.Errorf("hash composer.lock line %d for package %q", reg.line, pkg)
		}

		reg.hash = hash
		regs[pkg] = reg
	}

	return regs, nil
}

func parseRegions(data []byte) (regions, error) {
	// TODO: Find a way to read it in chunks instead of io.ReadAll
	lineBreaks := make([]int, 0, bytes.Count(data, []byte("\n")))
	for i, b := range data {
		if b == '\n' {
			lineBreaks = append(lineBreaks, i)
		}
	}

	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	if err := expectDelim(decoder, '{'); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	regs := make(regions)
	for decoder.PeekKind() != jsontext.KindEndObject {
		key, err := nextJSONString(decoder)
		if err != nil {
			return nil, fmt.Errorf("parse composer.lock: parse top level object key: %w", err)
		}

		switch key {
		case "packages", "packages-dev":
			if err = parsePackageArray(decoder, data, lineBreaks, regs); err != nil {
				return nil, fmt.Errorf("parse composer.lock: parse top level %s array: %w", key, err)
			}
		default:
			if err = decoder.SkipValue(); err != nil {
				return nil, fmt.Errorf("parse composer.lock: %w", err)
			}
		}
	}

	if err := expectDelim(decoder, '}'); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	return regs, nil
}

func parsePackageArray(decoder *jsontext.Decoder, data []byte, newlines []int, regions regions) error {
	if err := expectDelim(decoder, '['); err != nil {
		return err
	}

	for decoder.PeekKind() != jsontext.KindEndArray {
		if err := expectDelim(decoder, '{'); err != nil {
			return err
		}

		pkg, reg, err := locatePackageRegion(decoder, data, newlines)
		if err != nil {
			return err
		}

		if _, ok := regions[pkg]; ok {
			return fmt.Errorf("duplicate package %q", pkg)
		}
		regions[pkg] = reg

		if err := expectDelim(decoder, '}'); err != nil {
			return err
		}
	}

	return expectDelim(decoder, ']')
}

func locatePackageRegion(decoder *jsontext.Decoder, data []byte, newlines []int) (string, region, error) {
	var name string
	var offset int64

	for decoder.PeekKind() != jsontext.KindEndObject {
		key, err := nextJSONString(decoder)
		if err != nil {
			return "", region{}, fmt.Errorf("parse package field key: %w", err)
		}

		if key != "name" {
			if err := decoder.SkipValue(); err != nil {
				return "", region{}, err
			}
			continue
		}

		offset = decoder.InputOffset()
		val, err := nextJSONString(decoder)
		if err != nil {
			return "", region{}, fmt.Errorf("parse package name value: %w", err)
		}
		if val == "" {
			return "", region{}, errors.New("parse package name value: expected non-empty string")
		}
		name = val
	}

	if name == "" {
		return "", region{}, errors.New("package object missing name")
	}

	line := sort.SearchInts(newlines, int(offset)) + 1

	start := 0
	if line > 1 {
		start = newlines[line-2] + 1
	}
	end := len(data)
	if line > 1 && line-1 < len(newlines) {
		end = newlines[line-1]
	}

	lineData := data[start:end]
	startColumn := bytes.IndexByte(lineData, '"') + 1
	endColumn := bytes.LastIndexByte(lineData, '"') + 2

	r := region{
		line:        line,
		startColumn: startColumn,
		endColumn:   endColumn,
	}

	return name, r, nil
}

func expectDelim(decoder *jsontext.Decoder, want jsontext.Kind) error {
	tok, err := decoder.ReadToken()
	if err != nil {
		return err
	}

	if tok.Kind() != want {
		return fmt.Errorf("expected %q, got %v", want, tok)
	}

	return nil
}

func nextJSONString(decoder *jsontext.Decoder) (string, error) {
	tok, err := decoder.ReadToken()
	if err != nil {
		return "", err
	}

	if tok.Kind() != jsontext.KindString {
		return "", fmt.Errorf("expected JSON string literals, got %v", tok)
	}

	return tok.String(), nil
}
