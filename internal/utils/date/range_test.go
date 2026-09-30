package date

import "testing"

func TestIsMidnightNoopWindow(t *testing.T) {
	cases := []struct {
		name  string
		start string
		end   string
		want  bool
	}{
		{"exact midnight", "00:00", "00:00", true},
		{"whitespace tolerated", "  00:00 ", "00:00\t", true},
		{"only start midnight", "00:00", "23:59", false},
		{"only end midnight", "09:00", "00:00", false},
		{"non-midnight window", "09:00", "17:00", false},
		{"both empty", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMidnightNoopWindow(tc.start, tc.end); got != tc.want {
				t.Fatalf("IsMidnightNoopWindow(%q, %q) = %v, want %v", tc.start, tc.end, got, tc.want)
			}
		})
	}
}
