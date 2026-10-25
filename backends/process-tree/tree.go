// Package processtree implements fail-closed process-instance ancestry, independent of transport.
package processtree

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
)

type Identity struct {
	PID uint32
	// Started is the Windows creation FILETIME, in 100-nanosecond units since 1601 UTC.
	Started  uint64
	Sequence uint64
}

type Process struct {
	Identity
	ParentPID uint32
	Path      string
}

type Source interface{ Read(uint32) (Process, error) }

type Root struct {
	PID      uint32 `json:"pid,omitempty"`
	Started  uint64 `json:"started,omitempty"`
	Sequence uint64 `json:"sequence,omitempty"`
	Name     string `json:"name,omitempty"`
	Path     string `json:"path,omitempty"`
	SelfOnly bool   `json:"self_only,omitempty"`
}

func (r Root) Valid() bool {
	n := 0
	if r.PID > 4 && r.Started != 0 && r.Sequence != 0 {
		n++
	} else if r.PID != 0 || r.Started != 0 || r.Sequence != 0 {
		return false
	}
	if r.Name != "" {
		n++
		if strings.ContainsAny(r.Name, `/\`) {
			return false
		}
	}
	if r.Path != "" {
		n++
		if !filepath.IsAbs(r.Path) {
			return false
		}
	}
	if r.SelfOnly && r.PID == 0 {
		return false
	}
	return n == 1
}

type Result int

const (
	Unknown Result = iota
	Outside
	Inside
)

type lineage struct {
	chain    []Process
	complete bool
}

// Tracker never identifies an instance by PID alone. Its cache preserves proven ancestry
// after a parent exits. An unobserved orphan remains Unknown, never Outside.
type Tracker struct {
	source Source
	mu     sync.Mutex
	cache  map[Identity]lineage
}

func New(source Source) *Tracker { return &Tracker{source: source, cache: make(map[Identity]lineage)} }

func (t *Tracker) Match(owner Identity, root Root) Result {
	if !root.Valid() || owner.PID <= 4 || owner.Started == 0 || owner.Sequence == 0 {
		return Unknown
	}
	leaf, err := t.source.Read(owner.PID)
	if err != nil || leaf.Identity != owner {
		return Unknown
	}
	if root.SelfOnly {
		if root.PID == leaf.PID && root.Started == leaf.Started && root.Sequence == leaf.Sequence {
			return Inside
		}
		return Outside
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	trace := t.trace(leaf)
	for _, p := range trace.chain {
		if root.PID != 0 && root.PID == p.PID && root.Started == p.Started && root.Sequence == p.Sequence ||
			root.Name != "" && strings.EqualFold(filepath.Base(p.Path), root.Name) ||
			root.Path != "" && strings.EqualFold(p.Path, root.Path) {
			return Inside
		}
		// Use the kernel instance sequence, never wall-clock ordering. UTC can move backwards.
		if root.PID != 0 && p.Sequence < root.Sequence {
			return Outside
		}
	}
	if trace.complete {
		return Outside
	}
	return Unknown
}

func (t *Tracker) trace(leaf Process) lineage {
	if known, ok := t.cache[leaf.Identity]; ok {
		return known
	}
	chain := []Process{leaf}
	seen := map[Identity]bool{leaf.Identity: true}
	complete := false
	for len(chain) < 128 {
		child := chain[len(chain)-1]
		if child.ParentPID == 0 || child.ParentPID == 4 {
			complete = true
			break
		}
		parent, err := t.source.Read(child.ParentPID)
		if err != nil || parent.PID != child.ParentPID || parent.Started == 0 || parent.Sequence == 0 || parent.Sequence >= child.Sequence || seen[parent.Identity] {
			break
		}
		seen[parent.Identity] = true
		if known, ok := t.cache[parent.Identity]; ok {
			remaining := 128 - len(chain)
			if len(known.chain) > remaining {
				chain = append(chain, known.chain[:remaining]...)
			} else {
				chain = append(chain, known.chain...)
				complete = known.complete
			}
			break
		}
		chain = append(chain, parent)
	}
	value := lineage{chain, complete}
	// Bound memory. Eviction can turn an orphan into Unknown (blocked), never grant access.
	if len(t.cache) >= 4096 {
		t.cache = make(map[Identity]lineage)
	}
	t.cache[leaf.Identity] = value
	return value
}

var ErrUnavailable = errors.New("ProcessIdentityUnavailable")
