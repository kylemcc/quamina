package quamina

// matchSet is what it says on the tin; implements a set semantic on matches, which are of type X. These could all
// be implemented as match[X]bool but this makes the calling code more readable.
type matchSet struct {
	set map[X]bool
}

func newMatchSet() *matchSet {
	return &matchSet{set: make(map[X]bool)}
}

func (m *matchSet) addX(exes ...X) *matchSet {
	// for concurrency, can't update in place
	newSet := make(map[X]bool, len(m.set)+1)
	for k := range m.set {
		newSet[k] = true
	}
	for _, x := range exes {
		newSet[x] = true
	}
	return &matchSet{set: newSet}
}

func (m *matchSet) removeX(exes ...X) *matchSet {
	// for concurrency, can't update in place
	newSet := make(map[X]bool, len(m.set))
	for k := range m.set {
		newSet[k] = true
	}
	for _, x := range exes {
		delete(newSet, x)
	}
	return &matchSet{set: newSet}
}

func (m *matchSet) contains(x X) bool {
	_, ok := m.set[x]
	return ok
}

func (m *matchSet) matches() []X {
	matches := make([]X, 0, len(m.set))
	for x := range m.set {
		matches = append(matches, x)
	}
	return matches
}
