package utils

import "testing"

func TestAsBool(t *testing.T) {
	tests := []struct {
		in   any
		want bool
		err  bool
	}{
		{true, true, false}, {false, false, false},
		{"true", true, false}, {"True", true, false}, {"TRUE", true, false},
		{"false", false, false}, {"False", false, false}, {"FALSE", false, false},
		{"yes", false, true}, {42, false, true}, {nil, false, true},
	}
	for _, tc := range tests {
		got, err := AsBool(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("AsBool(%v) err = %v, wantErr %v", tc.in, err, tc.err)
			continue
		}
		if got != tc.want {
			t.Errorf("AsBool(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAsBoolExtended(t *testing.T) {
	tests := []struct {
		in   any
		want bool
		err  bool
	}{
		{true, true, false}, {false, false, false},
		{"true", true, false}, {"TRUE", true, false}, {" yes ", true, false}, {"on", true, false}, {"1", true, false},
		{"false", false, false}, {"NO", false, false}, {"off", false, false}, {"0", false, false},
		{"maybe", false, true}, {42, false, true}, {nil, false, true},
	}
	for _, tc := range tests {
		got, err := AsBoolExtended(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("AsBoolExtended(%v) err = %v, wantErr %v", tc.in, err, tc.err)
			continue
		}
		if got != tc.want {
			t.Errorf("AsBoolExtended(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
