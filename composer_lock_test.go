package comsarif

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func newDecoder(s string) *json.Decoder {
	return json.NewDecoder(strings.NewReader(s))
}

func TestExpectDelim(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    json.Delim
	}{
		{"open_brace", `{}`, '{'},
		{"open_bracket", `[]`, '['},
		{"close_brace_after_open", `{}`, '{'},
		{"close_bracket_after_open", `[]`, '['},
		{"nested_open_brace", `{  }`, '{'},
		{"open_brace_with_content", `{"key":"val"}`, '{'},
		{"open_bracket_with_content", `[1,2,3]`, '['},
		{"close_bracket_delim", `[]`, '['},
		{"close_brace_delim", `{}`, '{'},
		{"whitespace_before_brace", `   {  }`, '{'},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := newDecoder(tt.content)
			if err := expectDelim(dec, tt.want); err != nil {
				t.Fatalf("expectDelim() unexpected error: %v", err)
			}
		})
	}
}

func TestExpectDelim_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    json.Delim
	}{
		{"empty_input", ``, '{'},
		{"string_instead_of_delim", `"hello"`, '{'},
		{"number_instead_of_delim", `42`, '{'},
		{"bool_instead_of_delim", `true`, '{'},
		{"null_instead_of_delim", `null`, '{'},
		{"wrong_delim_brace_vs_bracket", `[`, '{'},
		{"wrong_delim_bracket_vs_brace", `{`, '['},
		{"close_instead_of_open", `}`, '{'},
		{"close_bracket_instead_of_open_brace", `]`, '{'},
		{"float_instead_of_delim", `3.14`, '{'},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := newDecoder(tt.content)
			if err := expectDelim(dec, tt.want); err == nil {
				t.Fatal("expectDelim() unexpected success")
			}
		})
	}
}

func TestNextJSONString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"simple_string", `"hello"`, "hello"},
		{"empty_string", `""`, ""},
		{"unicode_string", `"vendor/foo"`, "vendor/foo"},
		{"string_with_spaces", `"hello world"`, "hello world"},
		{"string_with_slash", `"foo/bar"`, "foo/bar"},
		{"string_with_escape", `"foo\"bar"`, `foo"bar`},
		{"number_like_string", `"42"`, "42"},
		{"string_with_unicode_escape", `"café"`, "café"},
		{"string_with_newline_escape", `"line1\nline2"`, "line1\nline2"},
		{"string_with_tab_escape", `"col1\tcol2"`, "col1\tcol2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := newDecoder(tt.content)
			got, err := nextJSONString(dec)
			if err != nil {
				t.Fatalf("nextJSONString() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("nextJSONString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNextJSONString_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{"empty_input", ``},
		{"number_token", `42`},
		{"bool_token", `true`},
		{"null_token", `null`},
		{"array_delim", `[`},
		{"object_delim", `{`},
		{"invalid_json", `@#$`},
		{"false_token", `false`},
		{"negative_number", `-1`},
		{"float_token", `3.14`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := newDecoder(tt.content)
			_, err := nextJSONString(dec)
			if err == nil {
				t.Fatal("nextJSONString() unexpected success")
			}
		})
	}
}

func TestSkipJSONValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"skip_string", `"hello" "next"`, false},
		{"skip_number", `42 "next"`, false},
		{"skip_bool_true", `true "next"`, false},
		{"skip_bool_false", `false "next"`, false},
		{"skip_null", `null "next"`, false},
		{"skip_empty_object", `{} "next"`, false},
		{"skip_empty_array", `[] "next"`, false},
		{"skip_nested_object", `{"a":{"b":1}} "next"`, false},
		{"skip_nested_array", `[[1,2],[3,4]] "next"`, false},
		{"skip_deep_nesting", `{"a":{"b":{"c":[1,2,3]}}} "next"`, false},
		{"empty_input", ``, true},
		{"truncated_object", `{"a":`, true},
		{"truncated_array", `[1,`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := newDecoder(tt.content)
			err := skipJSONValue(dec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("skipJSONValue() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLocatePackageRegion(t *testing.T) {
	t.Parallel()

	makeDecoderInObject := func(objJSON string) (*json.Decoder, []byte, []int) {
		data := []byte(objJSON)
		var newlines []int
		for i, b := range data {
			if b == '\n' {
				newlines = append(newlines, i)
			}
		}
		dec := json.NewDecoder(strings.NewReader(objJSON))
		_, _ = dec.Token()
		return dec, data, newlines
	}

	tests := []struct {
		name    string
		json    string
		want    string
		wantReg region
	}{
		{"name_only_field", `{"name":"vendor/pkg"}`, "vendor/pkg", region{line: 1, startColumn: 2, endColumn: 21}},
		{"name_after_other_fields", `{"version":"1.0","name":"vendor/pkg"}`, "vendor/pkg", region{line: 1, startColumn: 2, endColumn: 37}},
		{"name_before_other_fields", `{"name":"vendor/pkg","version":"1.0","description":"foo"}`, "vendor/pkg", region{line: 1, startColumn: 2, endColumn: 57}},
		{"name_with_nested_object_before_it", `{"extra":{"key":"val"},"name":"vendor/nested"}`, "vendor/nested", region{line: 1, startColumn: 2, endColumn: 46}},
		{"name_with_array_field", `{"keywords":["a","b"],"name":"vendor/arr"}`, "vendor/arr", region{line: 1, startColumn: 2, endColumn: 42}},
		{"many_fields_before_name", `{"a":"1","b":"2","c":"3","d":"4","name":"vendor/many"}`, "vendor/many", region{line: 1, startColumn: 2, endColumn: 54}},
		{
			"multiline_object_name_on_own_line",
			`{
"version":"1.0",
"name":"vendor/multi"
}`,
			"vendor/multi",
			region{line: 3, startColumn: 1, endColumn: 22},
		},
		{"name_with_deeply_nested_field_before_it", `{"require":{"php":"^8.0","ext-json":"*"},"name":"vendor/pkg2"}`, "vendor/pkg2", region{line: 1, startColumn: 2, endColumn: 62}},
		{"name_with_boolean_field_before_it", `{"abandoned":false,"name":"vendor/pkg3"}`, "vendor/pkg3", region{line: 1, startColumn: 2, endColumn: 40}},
		{"name_with_null_field_before_it", `{"homepage":null,"name":"vendor/pkg4"}`, "vendor/pkg4", region{line: 1, startColumn: 2, endColumn: 38}},
		{"nested_name_inside_extra_before", `{"extra":{"foo":{"name":"psr/log"}},"name":"monolog/monolog"}`, "monolog/monolog", region{line: 1, startColumn: 2, endColumn: 61}},
		{"nested_name_inside_extra_after", `{"name":"monolog/monolog","extra":{"foo":{"name":"psr/log"}}}`, "monolog/monolog", region{line: 1, startColumn: 2, endColumn: 59}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec, data, newlines := makeDecoderInObject(tt.json)
			pkg, reg, err := locatePackageRegion(dec, data, newlines)
			if err != nil {
				t.Fatalf("locatePackageRegion() unexpected error: %v", err)
			}
			if pkg != tt.want {
				t.Errorf("locatePackageRegion() = %q, want %q", pkg, tt.want)
			}
			if diff := cmp.Diff(tt.wantReg, reg, cmp.AllowUnexported(region{})); diff != "" {
				t.Errorf("locatePackageRegion() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLocatePackageRegion_Errors(t *testing.T) {
	t.Parallel()

	makeDecoderInObject := func(objJSON string) (*json.Decoder, []byte, []int) {
		data := []byte(objJSON)
		var newlines []int
		for i, b := range data {
			if b == '\n' {
				newlines = append(newlines, i)
			}
		}
		dec := json.NewDecoder(strings.NewReader(objJSON))
		_, _ = dec.Token()
		return dec, data, newlines
	}

	tests := []struct {
		name string
		json string
	}{
		{"missing_name_field", `{"version":"1.0","description":"foo"}`},
		{"empty_name_value", `{"name":""}`},
		{"name_value_is_number", `{"name":42}`},
		{"name_value_is_null", `{"name":null}`},
		{"name_value_is_bool", `{"name":true}`},
		{"name_value_is_array", `{"name":["a"]}`},
		{"name_value_is_object", `{"name":{"a":"b"}}`},
		{"empty_object_no_fields", `{}`},
		{"only_nested_object_no_name", `{"extra":{"a":"b"},"info":{"c":"d"}}`},
		{"name_value_is_false", `{"name":false}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec, data, newlines := makeDecoderInObject(tt.json)
			_, _, err := locatePackageRegion(dec, data, newlines)
			if err == nil {
				t.Fatal("locatePackageRegion() unexpected success")
			}
		})
	}
}

func TestParsePackageArray(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		content        string
		wantRegionKeys []string
	}{
		{"empty_array", `[]`, nil},
		{"single_package", `[{"name":"vendor/foo"}]`, []string{"vendor/foo"}},
		{"two_packages", `[{"name":"vendor/foo"},{"name":"vendor/bar"}]`, []string{"vendor/foo", "vendor/bar"}},
		{"package_with_extra_fields", `[{"version":"1.0","name":"vendor/pkg","description":"d"}]`, []string{"vendor/pkg"}},
		{"package_name_after_nested_object", `[{"extra":{"x":1},"name":"vendor/nested"}]`, []string{"vendor/nested"}},
		{"three_packages", `[{"name":"a/b"},{"name":"c/d"},{"name":"e/f"}]`, []string{"a/b", "c/d", "e/f"}},
		{"package_with_array_field_before_name", `[{"keywords":["x","y"],"name":"vendor/kw"}]`, []string{"vendor/kw"}},
		{"package_name_before_other_fields", `[{"name":"vendor/first","version":"2.0","description":"d"}]`, []string{"vendor/first"}},
		{"package_with_boolean_field", `[{"abandoned":true,"name":"vendor/old"}]`, []string{"vendor/old"}},
		{"package_with_null_field", `[{"homepage":null,"name":"vendor/nohome"}]`, []string{"vendor/nohome"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := []byte(tt.content)
			var newlines []int
			for i, b := range data {
				if b == '\n' {
					newlines = append(newlines, i)
				}
			}
			dec := json.NewDecoder(strings.NewReader(tt.content))
			regs := make(regions)
			if err := parsePackageArray(dec, data, newlines, regs); err != nil {
				t.Fatalf("parsePackageArray() unexpected error: %v", err)
			}
			opts := cmp.Options{
				cmpopts.SortSlices(func(a, b string) bool { return a < b }),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.wantRegionKeys, slices.Sorted(maps.Keys(regs)), opts); diff != "" {
				t.Errorf("parsePackageArray() keys mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParsePackageArray_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{"not_an_array", `{}`},
		{"duplicate_package", `[{"name":"vendor/foo"},{"name":"vendor/foo"}]`},
		{"package_missing_name", `[{"version":"1.0"}]`},
		{"package_with_empty_name", `[{"name":""}]`},
		{"truncated_array", `[{"name":"vendor/foo"`},
		{"malformed_JSON", `[{bad}]`},
		{"name_is_number", `[{"name":42}]`},
		{"name_is_null", `[{"name":null}]`},
		{"name_is_bool", `[{"name":false}]`},
		{"name_is_object", `[{"name":{"a":"b"}}]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := []byte(tt.content)
			var newlines []int
			for i, b := range data {
				if b == '\n' {
					newlines = append(newlines, i)
				}
			}
			dec := json.NewDecoder(strings.NewReader(tt.content))
			regs := make(regions)
			if err := parsePackageArray(dec, data, newlines, regs); err == nil {
				t.Fatal("parsePackageArray() unexpected success")
			}
		})
	}
}

func TestNewRegions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
		key  string
		want region
	}{
		{
			"simple",
			`{
    "packages": [
        {"name": "vendor/foo"}
    ]
}
`,
			"vendor/foo",
			region{line: 3, startColumn: 10, endColumn: 30, hash: "983435fd84409b6b:1"},
		},
		{
			"nested_name_in_packages_before",
			`{
    "packages": [
        {"extra":{"foo":{"name":"psr/log"}},"name":"monolog/monolog"},
        {"name":"psr/log"}
    ]
}`,
			"psr/log",
			region{line: 4, startColumn: 10, endColumn: 26, hash: "5a87f14a83c2596e:1"},
		},
		{
			"nested_name_in_packages_after",
			`{
    "packages": [
        {"name":"psr/log"},
        {"name":"monolog/monolog","extra":{"foo":{"name":"psr/log"}}}
    ]
}`,
			"psr/log",
			region{line: 3, startColumn: 10, endColumn: 26, hash: "22ad75b9acc5ec51:1"},
		},
		{
			"nested_name_in_packages_dev_before",
			`{
    "packages-dev": [
        {"extra":{"foo":{"name":"psr/log"}},"name":"monolog/monolog"},
        {"name":"psr/log"}
    ]
}`,
			"psr/log",
			region{line: 4, startColumn: 10, endColumn: 26, hash: "5a87f14a83c2596e:1"},
		},
		{
			"nested_name_in_packages_dev_after",
			`{
    "packages-dev": [
        {"name":"psr/log"},
        {"name":"monolog/monolog","extra":{"foo":{"name":"psr/log"}}}
    ]
}`,
			"psr/log",
			region{line: 3, startColumn: 10, endColumn: 26, hash: "22ad75b9acc5ec51:1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			regs, err := newRegions(strings.NewReader(tt.json))
			if err != nil {
				t.Fatalf("newRegions() unexpected error: %v", err)
			}
			got, ok := regs[tt.key]
			if !ok {
				t.Fatalf("newRegions() missing key %q", tt.key)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(region{})); diff != "" {
				t.Errorf("newRegions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewRegions_Keys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		json     string
		wantKeys []string
	}{
		{"empty_object", `{}`, nil},
		{"empty_packages_array", `{"packages":[]}`, nil},
		{"single_package_in_packages", `{"packages":[{"name":"vendor/foo"}]}`, []string{"vendor/foo"}},
		{"multiple_packages_in_packages", `{"packages":[{"name":"vendor/foo"},{"name":"vendor/bar"}]}`, []string{"vendor/foo", "vendor/bar"}},
		{"single_package_in_packages_dev", `{"packages-dev":[{"name":"vendor/dev"}]}`, []string{"vendor/dev"}},
		{"both_packages_and_packages_dev", `{"packages":[{"name":"vendor/foo"}],"packages-dev":[{"name":"vendor/dev"}]}`, []string{"vendor/foo", "vendor/dev"}},
		{"unknown_top_level_key_skipped", `{"content-hash":"abc123","packages":[{"name":"vendor/foo"}]}`, []string{"vendor/foo"}},
		{"unknown_key_with_object_value_skipped", `{"extra":{"key":"val"},"packages":[{"name":"vendor/foo"}]}`, []string{"vendor/foo"}},
		{"unknown_key_with_array_value_skipped", `{"aliases":["a","b"],"packages":[{"name":"vendor/foo"}]}`, []string{"vendor/foo"}},
		{"package_with_many_fields_before_name", `{"packages":[{"a":"1","b":"2","c":"3","d":"4","name":"vendor/many"}]}`, []string{"vendor/many"}},
		{"nested_packages_key_not_parsed_as_top_level", `{"packages":[{"name":"vendor/foo","packages":[{"name":"nested/pkg"}]}]}`, []string{"vendor/foo"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := newRegions(strings.NewReader(tt.json))
			if err != nil {
				t.Fatalf("newRegions() unexpected error: %v", err)
			}
			gotKeys := slices.Sorted(maps.Keys(got))

			opts := cmp.Options{
				cmpopts.SortSlices(func(a, b string) bool { return a < b }),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.wantKeys, gotKeys, opts); diff != "" {
				t.Errorf("newRegions() keys mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewRegions_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
	}{
		{"empty_input", ``},
		{"not_an_object_array", `[]`},
		{"not_an_object_string", `"hello"`},
		{"malformed_JSON", `{bad}`},
		{"truncated_object", `{"packages":[`},
		{"duplicate_package_across_arrays", `{"packages":[{"name":"vendor/foo"}],"packages-dev":[{"name":"vendor/foo"}]}`},
		{"package_missing_name", `{"packages":[{"version":"1.0"}]}`},
		{"package_with_empty_name", `{"packages":[{"name":""}]}`},
		{"package_name_is_number", `{"packages":[{"name":42}]}`},
		{"duplicate_package_within_same_array", `{"packages":[{"name":"vendor/foo"},{"name":"vendor/foo"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := newRegions(strings.NewReader(tt.json))
			if err == nil {
				t.Fatal("newRegions() unexpected success")
			}
		})
	}
}
