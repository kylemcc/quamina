package quamina

import (
	"fmt"
	"testing"
	"time"
)

// TestParseCIDR tests basic CIDR parsing for IPv4 and IPv6
func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		wantBottom  string
		wantTop     string
		expectError bool
	}{
		{
			name:       "IPv4 /24 network",
			cidr:       "192.168.1.0/24",
			wantBottom: "C0A80100",
			wantTop:    "C0A801FF",
		},
		{
			name:       "IPv4 /16 network",
			cidr:       "10.0.0.0/16",
			wantBottom: "0A000000",
			wantTop:    "0A00FFFF",
		},
		{
			name:       "IPv4 /8 network",
			cidr:       "172.16.0.0/8",
			wantBottom: "AC000000",
			wantTop:    "ACFFFFFF",
		},
		{
			name:       "IPv4 /32 single host",
			cidr:       "192.168.1.1/32",
			wantBottom: "C0A80101",
			wantTop:    "C0A80101",
		},
		{
			name:       "IPv4 /0 all addresses",
			cidr:       "0.0.0.0/0",
			wantBottom: "00000000",
			wantTop:    "FFFFFFFF",
		},
		{
			name:       "IPv4 /22 network",
			cidr:       "27.0.0.0/22",
			wantBottom: "1B000000",
			wantTop:    "1B0003FF",
		},
		{
			name:       "IPv6 /64 network",
			cidr:       "2001:db8::/64",
			wantBottom: "20010DB8000000000000000000000000",
			wantTop:    "20010DB800000000FFFFFFFFFFFFFFFF",
		},
		{
			name:       "IPv6 /48 network",
			cidr:       "2001:db8::/48",
			wantBottom: "20010DB8000000000000000000000000",
			wantTop:    "20010DB80000FFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:       "IPv6 /128 single host",
			cidr:       "2001:db8::1/128",
			wantBottom: "20010DB8000000000000000000000001",
			wantTop:    "20010DB8000000000000000000000001",
		},
		{
			name:       "IPv6 compressed notation",
			cidr:       "::1/128",
			wantBottom: "00000000000000000000000000000001",
			wantTop:    "00000000000000000000000000000001",
		},
		{
			name:        "Invalid - no slash",
			cidr:        "192.168.1.0",
			expectError: true,
		},
		{
			name:        "Invalid - bad IP",
			cidr:        "999.999.999.999/24",
			expectError: true,
		},
		{
			name:        "Invalid - negative mask",
			cidr:        "192.168.1.0/-5",
			expectError: true,
		},
		{
			name:        "Invalid - IPv4 mask too large",
			cidr:        "192.168.1.0/33",
			expectError: true,
		},
		{
			name:        "Invalid - IPv6 mask too large",
			cidr:        "2001:db8::/129",
			expectError: true,
		},
		{
			name:        "Invalid - non-numeric mask",
			cidr:        "192.168.1.0/foo",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := parseCIDR(tt.cidr)
			if tt.expectError {
				if err == nil {
					t.Errorf("parseCIDR(%q) expected error, got nil", tt.cidr)
				}
				return
			}
			if err != nil {
				t.Errorf("parseCIDR(%q) unexpected error: %v", tt.cidr, err)
				return
			}

			gotBottom := string(cr.bottom)
			gotTop := string(cr.top)

			if gotBottom != tt.wantBottom {
				t.Errorf("parseCIDR(%q) bottom = %q, want %q", tt.cidr, gotBottom, tt.wantBottom)
			}
			if gotTop != tt.wantTop {
				t.Errorf("parseCIDR(%q) top = %q, want %q", tt.cidr, gotTop, tt.wantTop)
			}
		})
	}
}

// TestIPToHex tests IP address to hex conversion
func TestIPToHex(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "Simple IPv4",
			ip:   "192.168.1.1",
			want: "C0A80101",
		},
		{
			name: "IPv4 all zeros",
			ip:   "0.0.0.0",
			want: "00000000",
		},
		{
			name: "IPv4 all 255s",
			ip:   "255.255.255.255",
			want: "FFFFFFFF",
		},
		{
			name: "IPv6 localhost",
			ip:   "::1",
			want: "00000000000000000000000000000001",
		},
		{
			name: "IPv6 full form",
			ip:   "2001:0db8:0000:0000:0000:ff00:0042:8329",
			want: "20010DB8000000000000FF0000428329",
		},
		{
			name: "IPv6 compressed",
			ip:   "2001:db8::ff00:42:8329",
			want: "20010DB8000000000000FF0000428329",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipToHexIfPossible(tt.ip)
			if got == nil {
				t.Errorf("ipToHexIfPossible(%q) returned nil", tt.ip)
				return
			}
			gotStr := string(got)
			if gotStr != tt.want {
				t.Errorf("ipToHexIfPossible(%q) = %q, want %q", tt.ip, gotStr, tt.want)
			}
		})
	}
}

// TestIPToHexIfPossible_NonIP tests that non-IP strings return nil
func TestIPToHexIfPossible_NonIP(t *testing.T) {
	tests := []string{
		"not-an-ip",
		"192.168.1",
		"999.999.999.999",
		"hello world",
		"",
		"foobar",
		"08:23", // Could match IPv6 regex but is not a valid IP
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			got := ipToHexIfPossible(input)
			if got != nil {
				t.Errorf("ipToHexIfPossible(%q) = %q, want nil", input, string(got))
			}
		})
	}
}

// TestIPToHexIfPossible_WithQuotes tests IP strings with JSON quotes
func TestIPToHexIfPossible_WithQuotes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: `"192.168.1.1"`,
			want:  "C0A80101",
		},
		{
			input: `"10.0.0.1"`,
			want:  "0A000001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ipToHexIfPossible(tt.input)
			if got == nil {
				t.Errorf("ipToHexIfPossible(%q) returned nil", tt.input)
				return
			}
			gotStr := string(got)
			if gotStr != tt.want {
				t.Errorf("ipToHexIfPossible(%q) = %q, want %q", tt.input, gotStr, tt.want)
			}
		})
	}
}

// TestDigitSequence tests the Range.digitSequence helper function for hex digits
func TestDigitSequence(t *testing.T) {
	tests := []struct {
		name         string
		first        byte
		last         byte
		includeFirst bool
		includeLast  bool
		want         string
	}{
		{
			name:         "Exclusive range",
			first:        '3',
			last:         'B',
			includeFirst: false,
			includeLast:  false,
			want:         "456789A",
		},
		{
			name:         "Include first only",
			first:        '3',
			last:         'B',
			includeFirst: true,
			includeLast:  false,
			want:         "3456789A",
		},
		{
			name:         "Include last only",
			first:        '3',
			last:         'B',
			includeFirst: false,
			includeLast:  true,
			want:         "456789AB",
		},
		{
			name:         "Inclusive range",
			first:        '3',
			last:         'B',
			includeFirst: true,
			includeLast:  true,
			want:         "3456789AB",
		},
		{
			name:         "Same digit, exclusive",
			first:        '5',
			last:         '5',
			includeFirst: false,
			includeLast:  false,
			want:         "",
		},
		{
			name:         "Same digit, inclusive",
			first:        '5',
			last:         '5',
			includeFirst: true,
			includeLast:  true,
			want:         "5",
		},
		{
			name:         "Full hex range",
			first:        '0',
			last:         'F',
			includeFirst: true,
			includeLast:  true,
			want:         "0123456789ABCDEF",
		},
	}

	// Create a dummy range with hex digits to test digitSequence
	r := &Range{
		bottom:    []byte{},
		top:       []byte{},
		digitSet:  []byte("0123456789ABCDEF"),
		rangeType: RangeTypeCIDR,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.digitSequence(tt.first, tt.last, tt.includeFirst, tt.includeLast)
			gotStr := string(got)
			if gotStr != tt.want {
				t.Errorf("digitSequence(%c, %c, %v, %v) = %q, want %q",
					tt.first, tt.last, tt.includeFirst, tt.includeLast, gotStr, tt.want)
			}
		})
	}
}

// TestCIDRNFAConstruction tests that CIDR NFAs are constructed without errors
func TestCIDRNFAConstruction(t *testing.T) {
	cidrs := []string{
		"10.0.0.0/8",
		"192.168.1.0/24",
		"172.16.0.0/12",
		"2001:db8::/32",
		"fe80::/10",
	}

	for _, cidr := range cidrs {
		t.Run(cidr, func(t *testing.T) {
			nfa, nextField, err := makeCIDRFA(cidr, sharedNullPrinter)
			if err != nil {
				t.Errorf("makeCIDRFA(%q) unexpected error: %v", cidr, err)
				return
			}
			if nfa == nil {
				t.Errorf("makeCIDRFA(%q) returned nil NFA", cidr)
			}
			if nextField == nil {
				t.Errorf("makeCIDRFA(%q) returned nil nextField", cidr)
			}
		})
	}
}

// TestCIDRNFAInvalidInput tests that invalid CIDRs produce errors
func TestCIDRNFAInvalidInput(t *testing.T) {
	invalidCIDRs := []string{
		"not-a-cidr",
		"192.168.1.0",        // no mask
		"192.168.1.0/33",     // invalid mask
		"999.999.999.999/24", // invalid IP
	}

	for _, cidr := range invalidCIDRs {
		t.Run(cidr, func(t *testing.T) {
			_, _, err := makeCIDRFA(cidr, sharedNullPrinter)
			if err == nil {
				t.Errorf("makeCIDRFA(%q) expected error, got nil", cidr)
			}
		})
	}
}

// TestCIDRRangeExtremes tests edge cases of CIDR ranges
func TestCIDRRangeExtremes(t *testing.T) {
	tests := []struct {
		name       string
		cidr       string
		wantBottom string
		wantTop    string
	}{
		{
			name:       "IPv4 /24",
			cidr:       "10.0.0.0/24",
			wantBottom: "0A000000",
			wantTop:    "0A0000FF",
		},
		{
			name:       "IPv4 /24 - CloudFront example",
			cidr:       "54.240.196.171/24",
			wantBottom: "36F0C400",
			wantTop:    "36F0C4FF",
		},
		{
			name:       "IPv4 /24 - non-zero host bits",
			cidr:       "192.0.2.0/24",
			wantBottom: "C0000200",
			wantTop:    "C00002FF",
		},
		{
			name:       "IPv4 /15 - AWS CloudFront range",
			cidr:       "13.32.0.0/15",
			wantBottom: "0D200000",
			wantTop:    "0D21FFFF",
		},
		{
			name:       "IPv4 /22",
			cidr:       "27.0.0.0/22",
			wantBottom: "1B000000",
			wantTop:    "1B0003FF",
		},
		{
			name:       "IPv4 /17",
			cidr:       "52.76.128.0/17",
			wantBottom: "344C8000",
			wantTop:    "344CFFFF",
		},
		{
			name:       "IPv4 /12",
			cidr:       "34.192.0.0/12",
			wantBottom: "22C00000",
			wantTop:    "22CFFFFF",
		},
		{
			name:       "IPv4 /31 - smallest non-host network",
			cidr:       "192.168.1.0/31",
			wantBottom: "C0A80100",
			wantTop:    "C0A80101",
		},
		{
			name:       "IPv6 /24 - compressed notation with host bits",
			cidr:       "0011:2233:4455:6677:8899:aabb:ccdd:eeff/24",
			wantBottom: "00112200000000000000000000000000",
			wantTop:    "001122FFFFFFFFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:       "IPv6 /24 - standard doc example",
			cidr:       "2001:db8::ff00:42:8329/24",
			wantBottom: "20010D00000000000000000000000000",
			wantTop:    "20010DFFFFFFFFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:       "IPv6 /24 - localhost",
			cidr:       "::1/24",
			wantBottom: "00000000000000000000000000000000",
			wantTop:    "000000FFFFFFFFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:       "IPv6 /28",
			cidr:       "2600:9000::/28",
			wantBottom: "26009000000000000000000000000000",
			wantTop:    "2600900FFFFFFFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:       "IPv6 /36",
			cidr:       "2600:1F11::/36",
			wantBottom: "26001F11000000000000000000000000",
			wantTop:    "26001F110FFFFFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:       "IPv6 /35",
			cidr:       "2600:1F14::/35",
			wantBottom: "26001F14000000000000000000000000",
			wantTop:    "26001F141FFFFFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:       "IPv6 /122 - small IPv6 network",
			cidr:       "2400:6500:FF00::36FB:1F80/122",
			wantBottom: "24006500FF0000000000000036FB1F80",
			wantTop:    "24006500FF0000000000000036FB1FBF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := parseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("parseCIDR(%q) error: %v", tt.cidr, err)
			}

			gotBottom := string(cr.bottom)
			gotTop := string(cr.top)

			if gotBottom != tt.wantBottom {
				t.Errorf("parseCIDR(%q) bottom = %q, want %q", tt.cidr, gotBottom, tt.wantBottom)
			}
			if gotTop != tt.wantTop {
				t.Errorf("parseCIDR(%q) top = %q, want %q", tt.cidr, gotTop, tt.wantTop)
			}
		})
	}
}

// TestInvalidIPNotMatchedByIPRegex tests that invalid IPs that might look like IPv6 are handled correctly
func TestInvalidIPNotMatchedByIPRegex(t *testing.T) {
	q, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// "08:23" might look like part of an IPv6 address but is not a valid IP
	// It should be treated as a regular string match, not an IP match
	pattern := `{"a": ["08:23"]}`
	event := `{"a": "08:23"}`

	err = q.AddPattern("r1", pattern)
	if err != nil {
		t.Fatalf("AddPattern() error: %v", err)
	}

	matches, err := q.MatchesForEvent([]byte(event))
	if err != nil {
		t.Fatalf("MatchesForEvent() error: %v", err)
	}

	if len(matches) != 1 || matches[0] != "r1" {
		t.Errorf("Expected match for pattern %q with event %q, got %v", pattern, event, matches)
	}
}

// TestSingleIPAddressMatching tests matching against single IP addresses (without CIDR notation)
func TestSingleIPAddressMatching(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		event       string
		shouldMatch bool
	}{
		// IPv4 tests
		{
			name:        "IPv4 exact match",
			pattern:     `{"ip": ["54.240.196.255"]}`,
			event:       `{"ip": "54.240.196.255"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 no match - off by one",
			pattern:     `{"ip": ["255.255.255.255"]}`,
			event:       `{"ip": "255.255.255.254"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv4 match all 255s",
			pattern:     `{"ip": ["255.255.255.255"]}`,
			event:       `{"ip": "255.255.255.255"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 specific IP",
			pattern:     `{"ip": ["255.255.255.5"]}`,
			event:       `{"ip": "255.255.255.5"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 specific IP no match",
			pattern:     `{"ip": ["255.255.255.10"]}`,
			event:       `{"ip": "255.255.255.11"}`,
			shouldMatch: false,
		},
		// IPv6 tests
		{
			name:        "IPv6 full form",
			pattern:     `{"ip": ["0011:2233:4455:6677:8899:aabb:ccdd:eeff"]}`,
			event:       `{"ip": "0011:2233:4455:6677:8899:aabb:ccdd:eeff"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 doc example",
			pattern:     `{"ip": ["2001:db8::ff00:42:8329"]}`,
			event:       `{"ip": "2001:db8::ff00:42:8329"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 compressed zero",
			pattern:     `{"ip": ["::0"]}`,
			event:       `{"ip": "::0"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 compressed three",
			pattern:     `{"ip": ["::3"]}`,
			event:       `{"ip": "::3"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 hex digit boundary test",
			pattern:     `{"ip": ["::9"]}`,
			event:       `{"ip": "::9"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 hex digit a",
			pattern:     `{"ip": ["::a"]}`,
			event:       `{"ip": "::a"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 hex digit f",
			pattern:     `{"ip": ["::f"]}`,
			event:       `{"ip": "::f"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 complex address",
			pattern:     `{"ip": ["2400:6500:FF00::36FB:1F80"]}`,
			event:       `{"ip": "2400:6500:FF00::36FB:1F80"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 complex address variant",
			pattern:     `{"ip": ["2400:6500:FF00::36FB:1F85"]}`,
			event:       `{"ip": "2400:6500:FF00::36FB:1F85"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 no match",
			pattern:     `{"ip": ["::1"]}`,
			event:       `{"ip": "::2"}`,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := New()
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			err = q.AddPattern("rule1", tt.pattern)
			if err != nil {
				t.Fatalf("AddPattern() error: %v", err)
			}

			matches, err := q.MatchesForEvent([]byte(tt.event))
			if err != nil {
				t.Fatalf("MatchesForEvent() error: %v", err)
			}

			matched := len(matches) > 0
			if matched != tt.shouldMatch {
				t.Errorf("Pattern %q with event %q: got match=%v, want match=%v",
					tt.pattern, tt.event, matched, tt.shouldMatch)
			}
		})
	}
}

// Integration tests - test full pattern matching with CIDR

// TestCIDRPatternMatching tests end-to-end CIDR pattern matching
func TestCIDRPatternMatching(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		event       string
		shouldMatch bool
	}{
		{
			name:        "IPv4 /24 - IP in range",
			pattern:     `{"sourceIP": [{"cidr": "192.168.1.0/24"}]}`,
			event:       `{"sourceIP": "192.168.1.100"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /24 - IP at bottom of range",
			pattern:     `{"sourceIP": [{"cidr": "192.168.1.0/24"}]}`,
			event:       `{"sourceIP": "192.168.1.0"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /24 - IP at top of range",
			pattern:     `{"sourceIP": [{"cidr": "192.168.1.0/24"}]}`,
			event:       `{"sourceIP": "192.168.1.255"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /24 - IP out of range",
			pattern:     `{"sourceIP": [{"cidr": "192.168.1.0/24"}]}`,
			event:       `{"sourceIP": "192.168.2.1"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv4 /16 - IP in range",
			pattern:     `{"sourceIP": [{"cidr": "10.0.0.0/16"}]}`,
			event:       `{"sourceIP": "10.0.200.50"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /16 - IP out of range",
			pattern:     `{"sourceIP": [{"cidr": "10.0.0.0/16"}]}`,
			event:       `{"sourceIP": "10.1.0.1"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv4 /8 - IP in range",
			pattern:     `{"sourceIP": [{"cidr": "172.0.0.0/8"}]}`,
			event:       `{"sourceIP": "172.16.254.1"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /32 - exact match",
			pattern:     `{"sourceIP": [{"cidr": "192.168.1.1/32"}]}`,
			event:       `{"sourceIP": "192.168.1.1"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /32 - no match",
			pattern:     `{"sourceIP": [{"cidr": "192.168.1.1/32"}]}`,
			event:       `{"sourceIP": "192.168.1.2"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv4 /32 - single address (Google DNS)",
			pattern:     `{"sourceIP": [{"cidr": "8.8.8.8/32"}]}`,
			event:       `{"sourceIP": "8.8.8.8"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /32 - single address no match",
			pattern:     `{"sourceIP": [{"cidr": "8.8.8.8/32"}]}`,
			event:       `{"sourceIP": "8.8.4.4"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv4 /32 - max address",
			pattern:     `{"sourceIP": [{"cidr": "255.255.255.255/32"}]}`,
			event:       `{"sourceIP": "255.255.255.255"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /32 - min address",
			pattern:     `{"sourceIP": [{"cidr": "0.0.0.0/32"}]}`,
			event:       `{"sourceIP": "0.0.0.0"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 /64 - IP in range",
			pattern:     `{"sourceIP": [{"cidr": "2001:db8::/64"}]}`,
			event:       `{"sourceIP": "2001:db8::1234"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 /64 - IP out of range",
			pattern:     `{"sourceIP": [{"cidr": "2001:db8::/64"}]}`,
			event:       `{"sourceIP": "2001:db8:1::1"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv6 /48 - exact bottom of range",
			pattern:     `{"sourceIP": [{"cidr": "2001:db8::/48"}]}`,
			event:       `{"sourceIP": "2001:db8::"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 /48 - IP in middle of range",
			pattern:     `{"sourceIP": [{"cidr": "2001:db8::/48"}]}`,
			event:       `{"sourceIP": "2001:db8:0:1234::5678"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 /48 - IP at end of variable part",
			pattern:     `{"sourceIP": [{"cidr": "2001:db8::/48"}]}`,
			event:       `{"sourceIP": "2001:db8:0:ffff:ffff:ffff:ffff:ffff"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 /48 - IP outside range (3rd group differs)",
			pattern:     `{"sourceIP": [{"cidr": "2001:db8::/48"}]}`,
			event:       `{"sourceIP": "2001:db8:1::"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv6 /48 - IP way outside range",
			pattern:     `{"sourceIP": [{"cidr": "2001:db8::/48"}]}`,
			event:       `{"sourceIP": "2001:db9::"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv6 /128 - exact match",
			pattern:     `{"sourceIP": [{"cidr": "::1/128"}]}`,
			event:       `{"sourceIP": "::1"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 /128 - no match",
			pattern:     `{"sourceIP": [{"cidr": "::1/128"}]}`,
			event:       `{"sourceIP": "::2"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv6 /128 - single address (full form)",
			pattern:     `{"sourceIP": [{"cidr": "2001:db8::1234/128"}]}`,
			event:       `{"sourceIP": "2001:db8::1234"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 /128 - single address no match",
			pattern:     `{"sourceIP": [{"cidr": "2001:db8::1234/128"}]}`,
			event:       `{"sourceIP": "2001:db8::1235"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv6 /128 - single address (all zeros)",
			pattern:     `{"sourceIP": [{"cidr": "::/128"}]}`,
			event:       `{"sourceIP": "::"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv6 /128 - single address (max)",
			pattern:     `{"sourceIP": [{"cidr": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"}]}`,
			event:       `{"sourceIP": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}`,
			shouldMatch: true,
		},
		{
			name:        "Multiple fields - all match",
			pattern:     `{"sourceIP": [{"cidr": "10.0.0.0/8"}], "destIP": [{"cidr": "192.168.0.0/16"}]}`,
			event:       `{"sourceIP": "10.1.2.3", "destIP": "192.168.1.1"}`,
			shouldMatch: true,
		},
		{
			name:        "Multiple fields - one doesn't match",
			pattern:     `{"sourceIP": [{"cidr": "10.0.0.0/8"}], "destIP": [{"cidr": "192.168.0.0/16"}]}`,
			event:       `{"sourceIP": "10.1.2.3", "destIP": "172.16.1.1"}`,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := New()
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			err = q.AddPattern("rule1", tt.pattern)
			if err != nil {
				t.Fatalf("AddPattern() error: %v", err)
			}

			matches, err := q.MatchesForEvent([]byte(tt.event))
			if err != nil {
				t.Fatalf("MatchesForEvent() error: %v", err)
			}

			matched := len(matches) > 0
			if matched != tt.shouldMatch {
				t.Errorf("Pattern %q with event %q: got match=%v, want match=%v",
					tt.pattern, tt.event, matched, tt.shouldMatch)
			}
		})
	}
}

// TestCIDRWithOtherPatterns tests CIDR patterns combined with other pattern types
func TestCIDRWithOtherPatterns(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		event       string
		shouldMatch bool
	}{
		{
			name:        "CIDR and exact string match",
			pattern:     `{"ip": [{"cidr": "10.0.0.0/8"}], "action": ["allow"]}`,
			event:       `{"ip": "10.5.5.5", "action": "allow"}`,
			shouldMatch: true,
		},
		{
			name:        "CIDR matches, string doesn't",
			pattern:     `{"ip": [{"cidr": "10.0.0.0/8"}], "action": ["allow"]}`,
			event:       `{"ip": "10.5.5.5", "action": "deny"}`,
			shouldMatch: false,
		},
		{
			name:        "CIDR and numeric match",
			pattern:     `{"ip": [{"cidr": "192.168.1.0/24"}], "port": [443]}`,
			event:       `{"ip": "192.168.1.50", "port": 443}`,
			shouldMatch: true,
		},
		{
			name:        "CIDR and prefix match",
			pattern:     `{"ip": [{"cidr": "172.16.0.0/12"}], "hostname": [{"prefix": "web-"}]}`,
			event:       `{"ip": "172.16.100.1", "hostname": "web-server-1"}`,
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := New()
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			err = q.AddPattern("rule1", tt.pattern)
			if err != nil {
				t.Fatalf("AddPattern() error: %v", err)
			}

			matches, err := q.MatchesForEvent([]byte(tt.event))
			if err != nil {
				t.Fatalf("MatchesForEvent() error: %v", err)
			}

			matched := len(matches) > 0
			if matched != tt.shouldMatch {
				t.Errorf("Pattern %q with event %q: got match=%v, want match=%v",
					tt.pattern, tt.event, matched, tt.shouldMatch)
			}
		})
	}
}

// TestMultipleCIDRPatterns tests multiple CIDR patterns in the same matcher
func TestMultipleCIDRPatterns(t *testing.T) {
	q, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Add multiple patterns with different CIDR blocks
	patterns := []struct {
		name    string
		pattern string
	}{
		{"private-10", `{"ip": [{"cidr": "10.0.0.0/8"}]}`},
		{"private-172", `{"ip": [{"cidr": "172.16.0.0/12"}]}`},
		{"private-192", `{"ip": [{"cidr": "192.168.0.0/16"}]}`},
	}

	for _, p := range patterns {
		err = q.AddPattern(p.name, p.pattern)
		if err != nil {
			t.Fatalf("AddPattern(%q) error: %v", p.name, err)
		}
	}

	tests := []struct {
		event       string
		wantMatches []string
	}{
		{
			event:       `{"ip": "10.1.2.3"}`,
			wantMatches: []string{"private-10"},
		},
		{
			event:       `{"ip": "172.16.5.10"}`,
			wantMatches: []string{"private-172"},
		},
		{
			event:       `{"ip": "192.168.1.1"}`,
			wantMatches: []string{"private-192"},
		},
		{
			event:       `{"ip": "8.8.8.8"}`,
			wantMatches: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.event, func(t *testing.T) {
			matches, err := q.MatchesForEvent([]byte(tt.event))
			if err != nil {
				t.Fatalf("MatchesForEvent() error: %v", err)
			}

			if len(matches) != len(tt.wantMatches) {
				t.Errorf("MatchesForEvent(%q): got %d matches, want %d",
					tt.event, len(matches), len(tt.wantMatches))
			}

			// Check that all expected matches are present
			matchSet := make(map[string]bool)
			for _, m := range matches {
				matchSet[m.(string)] = true
			}

			for _, want := range tt.wantMatches {
				if !matchSet[want] {
					t.Errorf("MatchesForEvent(%q): missing expected match %q",
						tt.event, want)
				}
			}
		})
	}
}

// TestCIDREdgeCases tests edge cases and boundary conditions
func TestCIDREdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		event       string
		shouldMatch bool
	}{
		{
			name:        "IPv4 /22 - IP at exact bottom",
			pattern:     `{"ip": [{"cidr": "27.0.0.0/22"}]}`,
			event:       `{"ip": "27.0.0.0"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /22 - IP at exact top",
			pattern:     `{"ip": [{"cidr": "27.0.0.0/22"}]}`,
			event:       `{"ip": "27.0.3.255"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /22 - IP just above top",
			pattern:     `{"ip": [{"cidr": "27.0.0.0/22"}]}`,
			event:       `{"ip": "27.0.4.0"}`,
			shouldMatch: false,
		},
		{
			name:        "IPv4 /15 - AWS CloudFront range",
			pattern:     `{"ip": [{"cidr": "13.32.0.0/15"}]}`,
			event:       `{"ip": "13.32.128.5"}`,
			shouldMatch: true,
		},
		{
			name:        "IPv4 /15 - Just outside range",
			pattern:     `{"ip": [{"cidr": "13.32.0.0/15"}]}`,
			event:       `{"ip": "13.34.0.1"}`,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := New()
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			err = q.AddPattern("rule1", tt.pattern)
			if err != nil {
				t.Fatalf("AddPattern() error: %v", err)
			}

			matches, err := q.MatchesForEvent([]byte(tt.event))
			if err != nil {
				t.Fatalf("MatchesForEvent() error: %v", err)
			}

			matched := len(matches) > 0
			if matched != tt.shouldMatch {
				t.Errorf("Pattern %q with event %q: got match=%v, want match=%v",
					tt.pattern, tt.event, matched, tt.shouldMatch)
			}
		})
	}
}

// TestCIDRPatternParsing tests that CIDR patterns are parsed correctly
func TestCIDRPatternParsing(t *testing.T) {
	validPatterns := []string{
		`{"ip": [{"cidr": "10.0.0.0/8"}]}`,
		`{"ip": [{"cidr": "192.168.1.0/24"}]}`,
		`{"ip": [{"cidr": "2001:db8::/32"}]}`,
	}

	for _, pattern := range validPatterns {
		t.Run(pattern, func(t *testing.T) {
			q, err := New()
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			err = q.AddPattern("test", pattern)
			if err != nil {
				t.Errorf("AddPattern(%q) unexpected error: %v", pattern, err)
			}
		})
	}

	invalidPatterns := []string{
		`{"ip": [{"cidr": "not-a-cidr"}]}`,
		`{"ip": [{"cidr": "192.168.1.0"}]}`,       // no mask
		`{"ip": [{"cidr": "192.168.1.0/33"}]}`,    // invalid mask
		`{"ip": [{"cidr": "999.999.999.999/8"}]}`, // invalid IP
	}

	for _, pattern := range invalidPatterns {
		t.Run(pattern, func(t *testing.T) {
			q, err := New()
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			err = q.AddPattern("test", pattern)
			if err == nil {
				t.Errorf("AddPattern(%q) expected error, got nil", pattern)
			}
		})
	}
}

// Test data for comprehensive CIDR matching tests
var (
	cidrRules = []string{
		"{\n" +
			"  \"sourceIP\": [ { \"cidr\": \"10.0.0.0/8\" } ]\n" +
			"}",
		"{\n" +
			"  \"sourceIP\": [ { \"cidr\": \"192.168.0.0/16\" } ]\n" +
			"}",
		"{\n" +
			"  \"sourceIP\": [ { \"cidr\": \"172.16.0.0/12\" } ]\n" +
			"}",
		"{\n" +
			"  \"sourceIP\": [ { \"cidr\": \"10.0.1.0/24\" } ]\n" +
			"}",
		"{\n" +
			"  \"sourceIP\": [ { \"cidr\": \"2001:db8::/32\" } ]\n" +
			"}",
	}
	// Note: r0 (10.0.0.0/8) also matches the 500 IPs from r3 (10.0.1.0/24) since it's a subset
	// So r0 gets 3000 + 500 = 3500 matches
	// r3 gets its 500 plus 1 overlap from the r0 generation = 501 matches
	cidrMatches = []int{3500, 2000, 1500, 501, 1000}
)

func getCIDREvents() [][]byte {
	// Generate test events with various IP addresses
	// This creates a mix of IPs that will match different CIDR patterns
	var events [][]byte

	// IPs matching 10.0.0.0/8 (3000 events)
	for i := 0; i < 3000; i++ {
		subnet := i % 256
		host := (i / 256) % 256
		event := fmt.Sprintf(`{"sourceIP": "10.%d.%d.%d"}`, subnet, host, i%256)
		events = append(events, []byte(event))
	}

	// IPs matching 192.168.0.0/16 (2000 events, some overlap with above)
	for i := 0; i < 2000; i++ {
		subnet := i % 256
		host := (i / 256) % 256
		event := fmt.Sprintf(`{"sourceIP": "192.168.%d.%d"}`, subnet, host)
		events = append(events, []byte(event))
	}

	// IPs matching 172.16.0.0/12 (1500 events)
	for i := 0; i < 1500; i++ {
		subnet := 16 + (i % 16)
		host1 := (i / 16) % 256
		host2 := (i / 4096) % 256
		event := fmt.Sprintf(`{"sourceIP": "172.%d.%d.%d"}`, subnet, host1, host2)
		events = append(events, []byte(event))
	}

	// IPs matching 10.0.1.0/24 (500 events, subset of 10.0.0.0/8)
	for i := 0; i < 500; i++ {
		event := fmt.Sprintf(`{"sourceIP": "10.0.1.%d"}`, i%256)
		events = append(events, []byte(event))
	}

	// IPv6 matching 2001:db8::/32 (1000 events)
	for i := 0; i < 1000; i++ {
		event := fmt.Sprintf(`{"sourceIP": "2001:db8::%x"}`, i)
		events = append(events, []byte(event))
	}

	// Add some non-matching IPs
	for i := 0; i < 1000; i++ {
		event := fmt.Sprintf(`{"sourceIP": "8.8.8.%d"}`, i%256)
		events = append(events, []byte(event))
	}

	return events
}

// TestRulerCIDR tests CIDR matching with a large set of events
func TestRulerCIDR(t *testing.T) {
	events := getCIDREvents()
	fmt.Printf("CIDR test events: %d\n", len(events))

	bm := newCIDRBenchmarker()
	bm.addRules(cidrRules, cidrMatches)
	fmt.Printf("CIDR events/sec: %.1f\n", bm.run(t, events))
}

// BenchmarkCIDR benchmarks CIDR pattern matching performance
func BenchmarkCIDR(b *testing.B) {
	var localMatches []X

	// Create Quamina instance and add CIDR patterns
	q, err := New()
	if err != nil {
		b.Fatalf("New(): %s", err.Error())
	}

	for i, rule := range cidrRules {
		rname := fmt.Sprintf("r%d", i)
		err = q.AddPattern(rname, rule)
		if err != nil {
			b.Fatalf("AddPattern(%s) failed: %s", rname, err.Error())
		}
	}

	// Log matcher stats
	b.Log(matcherStats(q.matcher.(*coreMatcher)))

	// Generate test events
	events := getCIDREvents()
	b.Logf("Testing with %d events", len(events))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		eventIndex := i % len(events)
		matches, err := q.MatchesForEvent(events[eventIndex])
		if err != nil {
			b.Errorf("MatchesForEvent: %s", err.Error())
		}
		localMatches = matches
	}

	topMatches = localMatches
}

// cidrBenchmarker is a helper for running CIDR benchmark tests
type cidrBenchmarker struct {
	wanted map[X]int
	q      *Quamina
}

func newCIDRBenchmarker() *cidrBenchmarker {
	q, _ := New()
	return &cidrBenchmarker{q: q, wanted: make(map[X]int)}
}

func (bm *cidrBenchmarker) addRules(rules []string, wanted []int) {
	for i, rule := range rules {
		rname := fmt.Sprintf("r%d", i)
		_ = bm.q.AddPattern(rname, rule)
		bm.wanted[rname] = wanted[i]
	}
}

func (bm *cidrBenchmarker) run(t *testing.T, events [][]byte) float64 {
	t.Helper()
	gotMatches := make(map[X]int)
	before := time.Now()
	for _, event := range events {
		matches, err := bm.q.MatchesForEvent(event)
		if err != nil {
			t.Error("m4e: " + err.Error())
		}
		for _, match := range matches {
			got, ok := gotMatches[match]
			if !ok {
				got = 1
			} else {
				got++
			}
			gotMatches[match] = got
		}
	}
	elapsed := float64(time.Since(before).Milliseconds())
	eps := float64(len(events)) / (elapsed / 1000.0)

	for match := range gotMatches {
		if bm.wanted[match] != gotMatches[match] {
			t.Errorf("for %s wanted %d got %d", match, bm.wanted[match], gotMatches[match])
		}
	}
	for match := range bm.wanted {
		got, ok := gotMatches[match]
		if !ok {
			got = 0
		}
		if bm.wanted[match] != got {
			t.Errorf("for %s wanted %d got %d", match, bm.wanted[match], got)
		}
	}
	return eps
}
