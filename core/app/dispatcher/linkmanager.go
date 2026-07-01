package dispatcher

import (
	sync "sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type ManagedWriter struct {
	writer  buf.Writer
	manager *LinkManager
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	return common.Close(w.writer)
}

type LinkManager struct {
	links  map[*ManagedWriter]buf.Reader
	mu     sync.RWMutex
	closed bool
}

// AddLink registers writer/reader and reports whether it succeeded. It
// returns false when this manager has already been closed (e.g. the user
// was just kicked/deleted via DelUsers -> CloseAll), so the caller can tell
// a stale manager apart from a live one and retry against a fresh one
// instead of silently dropping the new connection from tracking.
func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	m.links[writer] = reader
	return true
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		delete(m.links, writer)
	}
}

// registerManagedLink finds (or lazily creates) the live LinkManager for
// email in lms, wraps writer in a ManagedWriter tracked against it, and
// returns that ManagedWriter.
//
// Previously the two call sites (getLink/DispatchLink) did a plain
// Load-or-Store followed by an unconditional AddLink. That has a real race
// with DelUsers's CloseAll+Delete: if CloseAll marks the manager closed
// between this call's Load and its AddLink, the old AddLink (which returned
// nothing) silently dropped the registration — the connection kept working
// at the protocol level but became untracked, so a later rate-limit/kick
// for that user could never reach it. AddLink now reports success, and on
// failure we swap in a fresh manager (CompareAndSwap so concurrent retries
// converge on one winner) and retry.
func registerManagedLink(lms *sync.Map, email string, writer buf.Writer, reader buf.Reader) *ManagedWriter {
	for {
		var lm *LinkManager
		if v, ok := lms.Load(email); ok {
			lm = v.(*LinkManager)
		} else {
			actual, _ := lms.LoadOrStore(email, &LinkManager{links: make(map[*ManagedWriter]buf.Reader)})
			lm = actual.(*LinkManager)
		}
		managedWriter := &ManagedWriter{writer: writer, manager: lm}
		if lm.AddLink(managedWriter, reader) {
			return managedWriter
		}
		lms.CompareAndSwap(email, lm, &LinkManager{links: make(map[*ManagedWriter]buf.Reader)})
	}
}

func (m *LinkManager) CloseAll() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true

	links := m.links
	m.links = make(map[*ManagedWriter]buf.Reader)
	m.mu.Unlock()

	for w, r := range links {
		common.Close(w.writer)
		common.Interrupt(r)
	}
}
