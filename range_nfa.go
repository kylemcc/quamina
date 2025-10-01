package quamina

import "fmt"

// compileRange creates an NFA for matching values within a Range.
// This is a generalized version of the CIDR compilation algorithm that works
// with any digit set (hex for CIDR, base128 for numeric).
//
// Algorithm (from event-ruler):
// 1. Find the "fork offset" where bottom and top first differ
// 2. Build a common prefix path for identical leading bytes
// 3. At fork: any byte strictly between bottom[fork] and top[fork] matches
// 4. After fork on bottom path: any byte > bottom[i] matches (respecting openBottom)
// 5. After fork on top path: any byte < top[i] matches (respecting openTop)
func compileRange(r *Range, nextField *fieldMatcher, pp printer) *smallTable {
	if len(r.bottom) != len(r.top) {
		panic("Range bottom and top must have same length")
	}

	// Find fork offset where bottom and top first differ
	forkOffset := 0
	for forkOffset < len(r.bottom) && r.bottom[forkOffset] == r.top[forkOffset] {
		forkOffset++
	}

	// Build the common prefix path (states before the fork)
	var startTable *smallTable
	var forkState *faState

	if forkOffset == 0 {
		// No common prefix, start directly at fork
		forkState = &faState{table: newSmallTable()}
		startTable = forkState.table
	} else {
		// Build chain of states for common prefix
		startTable = newSmallTable()
		currentState := startTable
		for i := 0; i < forkOffset; i++ {
			nextState := &faState{table: newSmallTable()}
			if i == forkOffset-1 {
				forkState = nextState
			}
			currentState.addByteStep(r.bottom[i], nextState)
			currentState = nextState.table
		}
	}

	// At fork point, if there are bytes strictly between bottom[fork] and top[fork],
	// they all lead to immediate matches (any continuation matches)
	if forkOffset < len(r.bottom) {
		bottomByte := r.bottom[forkOffset]
		topByte := r.top[forkOffset]

		// Calculate remaining positions after the fork
		remainingPositions := len(r.bottom) - forkOffset - 1

		// Add transitions for bytes strictly between bottom and top at the fork
		// These bytes can be followed by ANY remaining digits
		for _, b := range r.digitSequence(bottomByte, topByte, false, false) {
			addRangeMatchForRemainingBytes(forkState.table, b, remainingPositions, r.digitSet, nextField, pp)
		}

		// Process the bottom path starting from fork position (exact match on bottom byte)
		// This handles: bottom[fork] followed by bytes >= bottom[fork+1...]
		processRangeBottomPath(forkState.table, r, forkOffset, nextField, pp)

		// Process the top path starting from fork position (exact match on top byte)
		// This handles: top[fork] followed by bytes <= top[fork+1...]
		processRangeTopPath(forkState.table, r, forkOffset, nextField, pp)
	} else {
		// Fork offset == length means bottom == top (single value)
		// This happens for single IPs (/32 or /128) or exact numeric matches
		// Need to handle open boundaries - if either boundary is open, no match
		if r.openBottom || r.openTop {
			// Open boundary on a single value means no matches
			// Don't add any transitions
		} else {
			// Closed boundaries on single value = exact match
			forkState.fieldTransitions = []*fieldMatcher{nextField}
		}
	}

	return startTable
}

// processRangeBottomPath handles the bottom boundary of the range.
// Starting from the fork position, we create a chain where matching the exact
// bottom byte at position i continues to position i+1, and matching a byte > bottom[i]
// at positions AFTER the fork leads to an immediate match.
//
// The openBottom flag controls whether the bottom boundary is inclusive (>=) or exclusive (>).
func processRangeBottomPath(forkTable *smallTable, r *Range, forkOffset int,
	nextField *fieldMatcher, pp printer) {

	if forkOffset >= len(r.bottom) {
		return
	}

	bottom := r.bottom
	maxDigit := r.maxDigit()

	// Create a chain of states following the bottom path
	currentState := forkTable
	for i := forkOffset; i < len(bottom); i++ {
		b := bottom[i]
		remainingPositions := len(bottom) - i - 1

		// At the fork position, DON'T add matches for bytes > bottom[i]
		// because those are handled by the middle bytes logic or top path.
		// Only add matches for bytes > bottom[i] at positions AFTER the fork.
		if i > forkOffset && b < maxDigit {
			for _, matchByte := range r.digitSequence(b, maxDigit, false, true) {
				addRangeMatchForRemainingBytes(currentState, matchByte, remainingPositions, r.digitSet, nextField, pp)
			}
		}

		// If at last position, handle the boundary condition
		if i == len(bottom)-1 {
			if r.openBottom {
				// Open bottom: > bottom, so don't match exact bottom value
				// Only match bytes > bottom[i] (already handled above if i > forkOffset)
				if i == forkOffset {
					// At fork, need to add matches for bytes > bottom[i]
					if b < maxDigit {
						for _, matchByte := range r.digitSequence(b, maxDigit, false, true) {
							addRangeMatchForRemainingBytes(currentState, matchByte, 0, r.digitSet, nextField, pp)
						}
					}
				}
			} else {
				// Closed bottom: >= bottom, so match exact bottom value
				addRangeMatchForRemainingBytes(currentState, b, 0, r.digitSet, nextField, pp)
			}
		} else {
			// Not at last position: create next state for exact match on bottom[i]
			nextState := findOrCreateNextState(currentState, b)
			currentState = nextState.table
		}
	}
}

// processRangeTopPath handles the top boundary of the range.
// Starting from the fork position, we create a chain where matching the exact
// top byte at position i continues to position i+1, and matching a byte < top[i]
// at positions AFTER the fork leads to an immediate match.
//
// The openTop flag controls whether the top boundary is inclusive (<=) or exclusive (<).
func processRangeTopPath(forkTable *smallTable, r *Range, forkOffset int,
	nextField *fieldMatcher, pp printer) {

	if forkOffset >= len(r.top) {
		return
	}

	top := r.top
	minDigit := r.minDigit()

	// Create a chain of states following the top path
	currentState := forkTable
	for i := forkOffset; i < len(top); i++ {
		b := top[i]
		remainingPositions := len(top) - i - 1

		// At the fork position, DON'T add matches for bytes < top[i]
		// because those are handled by the middle bytes logic or bottom path.
		// Only add matches for bytes < top[i] at positions AFTER the fork.
		if i > forkOffset && b > minDigit {
			for _, matchByte := range r.digitSequence(minDigit, b, true, false) {
				addRangeMatchForRemainingBytes(currentState, matchByte, remainingPositions, r.digitSet, nextField, pp)
			}
		}

		// If at last position, handle the boundary condition
		if i == len(top)-1 {
			if r.openTop {
				// Open top: < top, so don't match exact top value
				// Only match bytes < top[i] (already handled above if i > forkOffset)
				if i == forkOffset {
					// At fork, need to add matches for bytes < top[i]
					if b > minDigit {
						for _, matchByte := range r.digitSequence(minDigit, b, true, false) {
							addRangeMatchForRemainingBytes(currentState, matchByte, 0, r.digitSet, nextField, pp)
						}
					}
				}
			} else {
				// Closed top: <= top, so match exact top value
				addRangeMatchForRemainingBytes(currentState, b, 0, r.digitSet, nextField, pp)
			}
		} else {
			// Not at last position: create next state for exact match on top[i]
			nextState := findOrCreateNextState(currentState, b)
			currentState = nextState.table
		}
	}
}

// addRangeMatchForRemainingBytes adds a match for byte b followed by any valid digits
// for the remaining positions, then valueTerminator.
//
// This creates an NFA path: b -> [any digit]* -> valueTerminator -> nextField
// where [any digit]* means exactly remainingPositions digits from digitSet.
func addRangeMatchForRemainingBytes(table *smallTable, b byte, remainingPositions int,
	digitSet []byte, nextField *fieldMatcher, pp printer) {

	nextState := findOrCreateNextState(table, b)
	currentTable := nextState.table

	// For each remaining position, accept any digit from the digit set
	for i := 0; i < remainingPositions; i++ {
		// Create a state that accepts any digit
		newState := &faState{table: newSmallTable()}
		for _, digit := range digitSet {
			currentTable.addByteStep(digit, newState)
		}
		currentTable = newState.table
	}

	// After all positions consumed, match on valueTerminator
	matchState := &faState{
		table:            newSmallTable(),
		fieldTransitions: []*fieldMatcher{nextField},
	}
	currentTable.addByteStep(valueTerminator, matchState)
}

// makeRangeFA creates an NFA for matching a Range pattern.
// This is the main entry point for range pattern compilation.
func makeRangeFA(r *Range, label string, printer printer) (*smallTable, *fieldMatcher, error) {
	nextField := newFieldMatcher()
	nfa := compileRange(r, nextField, printer)
	printer.labelTable(nfa, fmt.Sprintf("Range:%s", label))
	return nfa, nextField, nil
}

// indexOfByte returns the index of b in bytes, or -1 if not found.
func indexOfByte(bytes []byte, b byte) int {
	for i, v := range bytes {
		if v == b {
			return i
		}
	}
	return -1
}

// findOrCreateNextState finds or creates the next state when transitioning on byte b.
func findOrCreateNextState(table *smallTable, b byte) *faState {
	next := table.dStep(b)
	if next != nil {
		return next
	}

	// Create new state
	nextState := &faState{table: newSmallTable()}
	table.addByteStep(b, nextState)
	return nextState
}
