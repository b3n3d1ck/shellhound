package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Hit is one indicator that fired on a file.
type Hit struct {
	Name    string `json:"indicator"`
	Kind    string `json:"kind"`
	Weight  int    `json:"weight"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet,omitempty"`
}

// Finding is a suspicious file and why it was flagged.
type Finding struct {
	Path        string `json:"path"`
	URL         string `json:"url,omitempty"`
	Size        int64  `json:"size"`
	Score       int    `json:"score"`
	Verdict     string `json:"verdict"`
	Masqueraded bool   `json:"masqueraded_extension"`
	Hits        []Hit  `json:"hits"`
}

type Report struct {
	Root        string    `json:"root"`
	FilesWalked int       `json:"files_walked"`
	FilesRead   int       `json:"files_read"`
	Findings    []Finding `json:"findings"`
	DurationMS  int64     `json:"duration_ms"`
}

type config struct {
	root        string
	exts        map[string]bool
	scanAllExt  bool
	skipDirs    map[string]bool
	minScore    int
	maxSize     int64
	urlBase     string
	concurrency int
}

// thresholds for the verbal verdict
func verdict(score int) string {
	switch {
	case score >= 70:
		return "KEMUNGKINAN BESAR WEBSHELL"
	case score >= 45:
		return "MENCURIGAKAN"
	case score >= 25:
		return "PERLU DITINJAU"
	}
	return ""
}

var phpOpen = []byte("<?php")
var phpShort = []byte("<?=")

type scanner struct {
	cfg config

	mu       sync.Mutex
	findings []Finding
	walked   int
	read     int
}

func newScanner(cfg config) *scanner { return &scanner{cfg: cfg} }

// Run walks the tree and analyzes every candidate file.
func (s *scanner) Run() Report {
	jobs := make(chan string, 256)
	var wg sync.WaitGroup
	workers := s.cfg.concurrency
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				s.analyze(p)
			}
		}()
	}

	filepath.WalkDir(s.cfg.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if s.cfg.skipDirs[d.Name()] && p != s.cfg.root {
				return filepath.SkipDir
			}
			return nil
		}
		s.mu.Lock()
		s.walked++
		s.mu.Unlock()
		jobs <- p
		return nil
	})
	close(jobs)
	wg.Wait()

	sort.Slice(s.findings, func(i, j int) bool {
		return s.findings[i].Score > s.findings[j].Score
	})
	return Report{
		Root:        s.cfg.root,
		FilesWalked: s.walked,
		FilesRead:   s.read,
		Findings:    s.findings,
	}
}

func (s *scanner) analyze(path string) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 || fi.Size() > s.cfg.maxSize {
		return
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	isPHPExt := s.cfg.exts[ext]

	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	// skip binaries (NUL byte early on)
	head := b
	if len(head) > 8192 {
		head = head[:8192]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return
	}

	masqueraded := false
	if !isPHPExt && !s.cfg.scanAllExt {
		// only inspect a non-PHP extension if it actually carries PHP code
		if !bytes.Contains(b, phpOpen) && !bytes.Contains(b, phpShort) {
			return
		}
		masqueraded = true
	}

	s.mu.Lock()
	s.read++
	s.mu.Unlock()

	hits, score := classify(b)
	if masqueraded {
		score += 25
		hits = append(hits, Hit{
			Name:   "ekstensi menyamar (kode PHP di file ." + ext + ")",
			Kind:   "penyamaran",
			Weight: 25,
		})
	}
	if score < s.cfg.minScore {
		return
	}
	v := verdict(score)
	if v == "" {
		return
	}

	f := Finding{
		Path:        path,
		Size:        fi.Size(),
		Score:       score,
		Verdict:     v,
		Masqueraded: masqueraded,
		Hits:        hits,
	}
	if s.cfg.urlBase != "" {
		if rel, err := filepath.Rel(s.cfg.root, path); err == nil {
			f.URL = strings.TrimRight(s.cfg.urlBase, "/") + "/" + filepath.ToSlash(rel)
		}
	}

	s.mu.Lock()
	s.findings = append(s.findings, f)
	s.mu.Unlock()
}

// classify runs every indicator against the body and returns the hits plus a
// total score. Each indicator counts once. If any execution/upload/obfuscation
// indicator fires together with user input, a bonus is added.
func classify(b []byte) ([]Hit, int) {
	lower := bytes.ToLower(b)
	var hits []Hit
	score := 0
	hasInput := false
	hasSink := false

	for _, ind := range indicators {
		var idx int = -1
		if ind.lit != "" {
			idx = bytes.Index(lower, []byte(strings.ToLower(ind.lit)))
		} else if ind.re != nil {
			if loc := ind.re.FindIndex(b); loc != nil {
				idx = loc[0]
			}
		}
		if idx < 0 {
			continue
		}
		if ind.kind == kInput {
			hasInput = true
			continue // scored only as a bonus below
		}
		if ind.kind == kSink || ind.kind == kObfus || ind.kind == kUpload {
			hasSink = true
		}
		line, snip := lineAt(b, idx)
		hits = append(hits, Hit{
			Name:    ind.name,
			Kind:    ind.kind.label(),
			Weight:  ind.weight,
			Line:    line,
			Snippet: maskLine(snip),
		})
		score += ind.weight
	}

	if hasInput && hasSink {
		score += 20
		hits = append(hits, Hit{
			Name:   "input user ($_GET/$_POST/...) berdekatan dengan fungsi berbahaya",
			Kind:   kInput.label(),
			Weight: 20,
		})
	}
	return hits, score
}

// lineAt returns the 1-based line number for byte offset idx and the trimmed
// text of that line.
func lineAt(b []byte, idx int) (int, string) {
	if idx < 0 || idx > len(b) {
		return 0, ""
	}
	line := 1 + bytes.Count(b[:idx], []byte("\n"))
	start := bytes.LastIndexByte(b[:idx], '\n') + 1
	end := bytes.IndexByte(b[idx:], '\n')
	if end < 0 {
		end = len(b)
	} else {
		end = idx + end
	}
	return line, strings.TrimSpace(string(b[start:end]))
}
