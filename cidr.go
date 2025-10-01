package quamina

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Bit masks for computing CIDR ranges.
// leadingBitMask[n] has the leading (8-n) bits set to 1, trailing n bits set to 0.
// Binary: 11111111, 11111110, 11111100, 11111000, 11110000, 11100000, 11000000, 10000000, 00000000
var leadingBitMask = []byte{
	0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80, 0x00,
}

// trailingBitMask[n] has the leading (8-n) bits set to 0, trailing n bits set to 1.
// Binary: 00000000, 00000001, 00000011, 00000111, 00001111, 00011111, 00111111, 01111111, 11111111
var trailingBitMask = []byte{
	0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff,
}

// hexDigits used for IP to hex conversion
var hexDigits = []byte("0123456789ABCDEF")

// makeCIDRFA creates an NFA for matching IP addresses within a CIDR range.
func makeCIDRFA(cidr string, printer printer) (*smallTable, *fieldMatcher, error) {
	r, err := parseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	return makeRangeFA(r, cidr, printer)
}

// parseCIDR parses CIDR notation (e.g., "192.168.1.0/24") and returns a Range.
// Supports both IPv4 and IPv6 CIDR notation.
// The returned Range uses hex digit encoding and has closed boundaries (inclusive).
func parseCIDR(cidr string) (*Range, error) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed CIDR, one '/' required")
	}

	// Parse IP address
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", parts[0])
	}

	// Parse mask bits
	maskBits, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed CIDR, mask bits must be an integer")
	}
	if maskBits < 0 {
		return nil, fmt.Errorf("malformed CIDR, mask bits must not be negative")
	}

	// Normalize to IPv4 or IPv6
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		if maskBits > 32 {
			return nil, fmt.Errorf("IPv4 mask bits must be <= 32")
		}
		return computeCIDRRange(ip4, maskBits, 32)
	}

	// IPv6
	if maskBits > 128 {
		return nil, fmt.Errorf("IPv6 mask bits must be <= 128")
	}
	return computeCIDRRange(ip.To16(), maskBits, 128)
}

// computeCIDRRange computes the bottom and top IP addresses of a CIDR range.
// It takes the base IP bytes, the number of mask bits (fixed prefix length),
// and the total number of bits in the address.
// Returns a Range with hex-encoded boundaries and closed (inclusive) bounds.
func computeCIDRRange(ipBytes []byte, maskBits, totalBits int) (*Range, error) {
	variableBits := totalBits - maskBits

	minBytes := make([]byte, len(ipBytes))
	maxBytes := make([]byte, len(ipBytes))

	// Process from least significant to most significant byte (right to left)
	for i := len(ipBytes) - 1; i >= 0; i-- {
		if variableBits > 0 {
			// This byte has some variable bits
			bitsInByte := variableBits
			if bitsInByte > 8 {
				bitsInByte = 8
			}

			// Min: keep fixed (leading) bits from IP, set variable (trailing) bits to 0
			minBytes[i] = ipBytes[i] & leadingBitMask[bitsInByte]

			// Max: keep fixed (leading) bits from IP, set variable (trailing) bits to 1
			maxBytes[i] = ipBytes[i] | trailingBitMask[bitsInByte]

			variableBits -= 8
		} else {
			// This byte is entirely fixed
			minBytes[i] = ipBytes[i]
			maxBytes[i] = ipBytes[i]
		}
	}

	// Create Range with hex digit set and closed boundaries
	// CIDR ranges are always inclusive: [min, max]
	return newRange(
		ipToHex(minBytes),
		ipToHex(maxBytes),
		false, // openBottom = false (inclusive >=)
		false, // openTop = false (inclusive <=)
		hexDigits,
		RangeTypeCIDR,
	)
}

// ipToHex converts IP address bytes to a hexadecimal string representation.
// Each byte is converted to two hex digits (uppercase).
// Example: []byte{192, 168, 1, 0} -> []byte("C0A80100")
func ipToHex(ipBytes []byte) []byte {
	result := make([]byte, len(ipBytes)*2)
	for i, b := range ipBytes {
		result[i*2] = hexDigits[(b>>4)&0x0F]
		result[i*2+1] = hexDigits[b&0x0F]
	}
	return result
}

// ipToHexIfPossible attempts to parse a string as an IP address and convert it to hex.
// If successful, returns the hex representation. If not an IP, returns the original string.
// This is used during event matching to convert IP literals to comparable hex form.
func ipToHexIfPossible(ipStr string) []byte {
	// Strip quotes if present (JSON string values)
	if len(ipStr) > 2 && ipStr[0] == '"' && ipStr[len(ipStr)-1] == '"' {
		ipStr = ipStr[1 : len(ipStr)-1]
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Normalize to IPv4 or IPv6
	if ip4 := ip.To4(); ip4 != nil {
		return ipToHex(ip4)
	}
	return ipToHex(ip.To16())
}
