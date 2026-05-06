package comsarif

import (
	"bytes"
	"encoding/json"
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
}

func newRegions(r io.Reader) (regions, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read composer.lock JSON: %v", err)
	}

	// TODO: Find a way to read it in chunks instead of io.ReadAll
	eol := []byte{'\n'}
	lineBreaks := make([]int, 0, bytes.Count(data, eol))
	haystack := bytes.Clone(data)
	for x, d := bytes.Index(haystack, eol), 0; x > -1; x, d = bytes.Index(haystack, eol), d+x+1 {
		lineBreaks = append(lineBreaks, x+d)
		haystack = haystack[x+1:]
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := expectDelim(decoder, '{'); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %v", err)
	}

	regs := make(regions)
	for decoder.More() {
		key, err := nextJSONString(decoder)
		if err != nil {
			return nil, fmt.Errorf("parse composer.lock: parse top level object key: %v", err)
		}

		switch key {
		case "packages", "packages-dev":
			if err = parsePackageArray(decoder, data, lineBreaks, regs); err != nil {
				return nil, fmt.Errorf("parse composer.lock: parse top level %s array: %v", key, err)
			}
		default:
			if err = skipJSONValue(decoder); err != nil {
				return nil, fmt.Errorf("parse composer.lock: %v", err)
			}
		}
	}

	if err := expectDelim(decoder, '}'); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %v", err)
	}

	return regs, nil
}

func parsePackageArray(decoder *json.Decoder, data []byte, newlines []int, regions regions) error {
	if err := expectDelim(decoder, '['); err != nil {
		return err
	}

	for decoder.More() {
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

func locatePackageRegion(decoder *json.Decoder, data []byte, newlines []int) (string, region, error) {
	var name string
	var offset int64

	for decoder.More() {
		key, err := nextJSONString(decoder)
		if err != nil {
			return "", region{}, fmt.Errorf("parse package field key: %v", err)
		}

		if key != "name" {
			if err := skipJSONValue(decoder); err != nil {
				return "", region{}, err
			}
			continue
		}

		offset = decoder.InputOffset()
		val, err := nextJSONString(decoder)
		if err != nil {
			return "", region{}, fmt.Errorf("parse package name value: %v", err)
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
	endColumn := bytes.LastIndexByte(lineData, '"') + 1

	r := region{
		line:        line,
		startColumn: startColumn,
		endColumn:   endColumn,
	}

	return name, r, nil
}

func expectDelim(decoder *json.Decoder, want json.Delim) error {
	tok, err := decoder.Token()
	if err != nil {
		return err
	}

	delim, ok := tok.(json.Delim)
	if !ok || delim != want {
		return fmt.Errorf("expected %q, got %T %v", want, tok, tok)
	}

	return nil
}

func nextJSONString(decoder *json.Decoder) (string, error) {
	tok, err := decoder.Token()
	if err != nil {
		return "", err
	}

	val, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected JSON string literals, got %T %v", tok, tok)
	}

	return val, nil
}

func skipJSONValue(decoder *json.Decoder) error {
	tok, err := decoder.Token()
	if err != nil {
		return err
	}

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
		return expectDelim(decoder, '}')
	case '[':
		for decoder.More() {
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
		return expectDelim(decoder, ']')
	default:
		return nil
	}
}
