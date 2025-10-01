package quamina

import (
	"bytes"
	"errors"
)

// RangeType distinguishes between different types of range patterns
type RangeType int

const (
	// RangeTypeCIDR represents IP address CIDR ranges (uses hex digits)
	RangeTypeCIDR RangeType = iota
	// RangeTypeNumeric represents numeric value ranges (uses Q-number encoding)
	RangeTypeNumeric
)

// Range represents a numeric range pattern matcher.
// It matches values that fall within [bottom, top], with optional open boundaries.
// This unified type handles both CIDR IP ranges and numeric value ranges.
type Range struct {
	// bottom and top define the range boundaries as encoded byte strings
	bottom []byte
	top    []byte

	// openBottom=true means > bottom (exclusive), false means >= bottom (inclusive)
	openBottom bool
	// openTop=true means < top (exclusive), false means <= top (inclusive)
	openTop bool

	// digitSet is the set of valid digits for this range type
	// For CIDR: "0123456789ABCDEF" (hex digits)
	// For numeric: base128 digit set from Q-number encoding
	digitSet []byte

	// rangeType identifies whether this is a CIDR or numeric range
	rangeType RangeType
}

// newRange creates a new Range with validation.
// bottom and top must be the same length.
// For valid ranges: bottom <= top, with bottom == top allowed only when both boundaries are closed.
func newRange(bottom, top []byte, openBottom, openTop bool, digitSet []byte, rangeType RangeType) (*Range, error) {
	if len(bottom) != len(top) {
		return nil, errors.New("range bottom and top must have same length")
	}

	// Validate that bottom <= top
	if err := validateRangeBounds(bottom, top, openBottom, openTop); err != nil {
		return nil, err
	}

	return &Range{
		bottom:     bottom,
		top:        top,
		openBottom: openBottom,
		openTop:    openTop,
		digitSet:   digitSet,
		rangeType:  rangeType,
	}, nil
}

// validateRangeBounds ensures bottom <= top lexicographically.
// If bottom == top, both boundaries must be closed (inclusive).
// Returns error if bottom > top, or if bottom == top with open boundaries.
func validateRangeBounds(bottom, top []byte, openBottom, openTop bool) error {
	cmp := bytes.Compare(bottom, top)
	if cmp > 0 {
		return errors.New("range bottom must be less than or equal to top")
	}
	if cmp == 0 && (openBottom || openTop) {
		// bottom == top with open boundary means no values match
		return errors.New("range with equal bounds must have closed boundaries")
	}
	return nil
}

// digitSequence returns a slice of digits from the range's digit set.
// It returns digits in [first, last] with inclusive/exclusive boundaries
// controlled by includeFirst and includeLast.
//
// This is the core helper for range NFA compilation, used to determine
// which byte transitions to add at each position.
//
// Example (hex digits):
//
//	digitSequence('3', 'C', false, false) -> "456789AB"
//	digitSequence('3', 'C', true, false)  -> "3456789AB"
//	digitSequence('3', 'C', false, true)  -> "456789ABC"
//	digitSequence('3', 'C', true, true)   -> "3456789ABC"
func (r *Range) digitSequence(first, last byte, includeFirst, includeLast bool) []byte {
	firstIdx := indexOfByte(r.digitSet, first)
	lastIdx := indexOfByte(r.digitSet, last)

	if firstIdx == -1 || lastIdx == -1 {
		return nil
	}

	if !includeFirst {
		firstIdx++
	}

	if includeLast {
		lastIdx++
	}

	if firstIdx >= lastIdx {
		return nil
	}

	return r.digitSet[firstIdx:lastIdx]
}

// minDigit returns the smallest digit in this range's digit set
func (r *Range) minDigit() byte {
	if len(r.digitSet) == 0 {
		return 0
	}
	return r.digitSet[0]
}

// maxDigit returns the largest digit in this range's digit set
func (r *Range) maxDigit() byte {
	if len(r.digitSet) == 0 {
		return 0
	}
	return r.digitSet[len(r.digitSet)-1]
}
