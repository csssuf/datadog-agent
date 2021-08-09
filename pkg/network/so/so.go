package so

import (
	"path/filepath"
	"regexp"
	"strconv"
)

// AllLibraries represents a filter that matches all shared libraries
var AllLibraries = regexp.MustCompile(`\.so($|\.)`)

// Find returns the host-resolved paths of all shared libraries (per mount namespace) matching the given filter
// It does so by iterating over all /proc/<PID>/maps and /proc/<PID>/mountinfo files in the host
// If filter is nil, all entries from /proc/<PID>/maps with a pathname are reported
func Find(procRoot string, filter *regexp.Regexp) []Library {
	finder := newFinder(procRoot)
	return finder.Find(filter)
}

// FromPID returns all shared libraries matching the given filter that are mapped into memory by a given PID
// If filter is nil, all entries from /proc/<PID>/maps with a pathname are reported
func FromPID(procRoot string, pid int32, filter *regexp.Regexp) []Library {
	pidPath := filepath.Join(procRoot, strconv.Itoa(int(pid)))
	finder := newFinder(pidPath)
	return finder.Find(filter)
}
