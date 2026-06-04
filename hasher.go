package comsarif

import (
	"fmt"
	"unicode/utf16"
)

// primaryLocationLineHashesByLine computes hashes with
// github/codeql-action/upload-sarif action's [algorithm].
//
// [algorithm]: https://github.com/github/codeql-action/blob/048d0ea295b6784a80010b29fd3af3ee29461dcd/src/fingerprints.ts
func primaryLocationLineHashesByLine(data []byte) map[int]string {
	h := newHasher()

	for _, codeUnit := range utf16.Encode([]rune(string(data))) {
		h.processCharacter(uint64(codeUnit))
	}
	h.processCharacter(lineHashEOF)

	for range lineHashBlockSize {
		h.flush()
	}

	return h.lineHashes
}

const (
	lineHashBlockSize = 100
	lineHashMod       = uint64(37)
	lineHashEOF       = uint64(65535)
)

type hasher struct {
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

func newHasher() *hasher {
	h := &hasher{
		hashCounts: make(map[string]int),
		lineHashes: make(map[int]string),
		firstMod:   lineHashFirstMod(),
		lineStart:  true,
	}
	for i := range h.lineNumbers {
		h.lineNumbers[i] = -1
	}
	return h
}

func (h *hasher) flush() {
	if h.lineNumbers[h.index] != -1 {
		h.outputHash()
	}
	h.updateHash(0)
}

func (h *hasher) outputHash() {
	hashValue := fmt.Sprintf("%x", h.hashRaw)
	h.hashCounts[hashValue]++
	h.lineHashes[h.lineNumbers[h.index]] = fmt.Sprintf("%s:%d", hashValue, h.hashCounts[hashValue])
	h.lineNumbers[h.index] = -1
}

func (h *hasher) updateHash(current uint64) {
	begin := h.window[h.index]
	h.window[h.index] = current
	h.hashRaw = lineHashMod*h.hashRaw + current - h.firstMod*begin
	h.index = (h.index + 1) % lineHashBlockSize
}

func (h *hasher) processCharacter(current uint64) {
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

func (h *hasher) shouldSkipCharacter(current uint64) bool {
	return current == ' ' || current == '\t' || (h.prevCR && current == '\n')
}

func (h *hasher) normalizeCharacter(current uint64) uint64 {
	if current == '\r' {
		h.prevCR = true
		return '\n'
	}
	h.prevCR = false
	return current
}

func lineHashFirstMod() uint64 {
	firstMod := uint64(1)
	for range lineHashBlockSize {
		firstMod *= lineHashMod
	}
	return firstMod
}
