package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Mode URL — penelusuran pasif dari sebuah link.
//
// Murni membaca apa yang server tampilkan sendiri: menelusuri path dari link,
// robots, sitemap, dan JS (tanpa wordlist), lalu hanya melaporkan yang 200.
// Mengenali halaman login, uploader, dan halaman yang isinya mirip webshell.
// Plus info host (IP, reverse DNS, server) dan daftar kelemahan + cara fix.
// Hanya mengirim GET. Tidak ada brute-force, tidak memaksa apa pun terbuka.
// ============================================================================

type urlConfig struct {
	timeout     time.Duration
	insecure    bool
	ua          string
	concurrency int
	depth       int
}

type URLWeak struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

type URLPath struct {
	Path   string `json:"path"`
	URL    string `json:"url"`
	Length int    `json:"length"`
	Title  string `json:"title,omitempty"`
	Source string `json:"source"`
}

type URLHit struct {
	Path string `json:"path"`
	URL  string `json:"url"`
	Kind string `json:"kind"` // login, uploader, webshell
	Note string `json:"note,omitempty"`
}

type URLReport struct {
	Target     string    `json:"target"`
	IPs        []string  `json:"ips"`
	ReverseDNS []string  `json:"reverse_dns,omitempty"`
	Server     string    `json:"server,omitempty"`
	Tech       []string  `json:"tech"`
	Paths      []URLPath `json:"paths_200"`
	Hits       []URLHit  `json:"hits"`
	Weaknesses []URLWeak `json:"weaknesses"`
	Requests   int       `json:"requests"`
	DurationMS int64     `json:"duration_ms"`
}

func isURL(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// ---- detectors (content of pages we already fetched) ----

var (
	uTitle   = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	uHref    = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#\s>]+)`)
	uLoc     = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)`)
	uRobots  = regexp.MustCompile(`(?im)^\s*(?:dis)?allow\s*:\s*(\S+)`)
	uJSPath  = regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9._\-/]{1,}(?:\.(?:php|json|js|html?|aspx?|do|action)|/)[a-zA-Z0-9._~:/?#\[\]@!$&()*+,;=%\-]{0,}|/api/[a-zA-Z0-9._\-/]{1,})["'` + "`" + `]`)
	uLogin   = regexp.MustCompile(`(?i)<input[^>]+type=["']password["']|name=["']pass(?:word)?["']`)
	uUpload  = regexp.MustCompile(`(?i)type=["']file["']|enctype=["']multipart/form-data`)
	uDirList = regexp.MustCompile(`(?i)<title>\s*index of /|>\s*Parent Directory\s*<`)
	uShell   = regexp.MustCompile(`(?i)c99shell|r57shell|b374k|filesman|wso\s*\d|wsoshell|indoxploit|alfa team|p0wny|<title>[^<]*\bshell\b|\$auth_pass|uname -a</`)
	uHasVer  = regexp.MustCompile(`\d`)
)

var uSecHeaders = []struct{ key, label, sev, fix string }{
	{"content-security-policy", "Content-Security-Policy", "SEDANG", "Set header CSP; mulai dari `default-src 'self'`."},
	{"strict-transport-security", "Strict-Transport-Security", "SEDANG", "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`."},
	{"x-frame-options", "X-Frame-Options", "RENDAH", "Set `X-Frame-Options: SAMEORIGIN` untuk cegah clickjacking."},
	{"x-content-type-options", "X-Content-Type-Options", "RENDAH", "Set `X-Content-Type-Options: nosniff`."},
	{"referrer-policy", "Referrer-Policy", "RENDAH", "Set `Referrer-Policy: strict-origin-when-cross-origin`."},
	{"permissions-policy", "Permissions-Policy", "RENDAH", "Batasi fitur browser lewat `Permissions-Policy`."},
}

// ---- scanner ----

type uResp struct {
	status  int
	headers http.Header
	body    []byte
	ct      string
}

type urlScanner struct {
	cl   *http.Client
	cfg  urlConfig
	base *url.URL

	mu    sync.Mutex
	seen  map[string]bool
	paths []URLPath
	hits  []URLHit
	weaks []URLWeak
	req   int
	sem   chan struct{}
}

func runURLScan(raw string, cfg urlConfig, asJSON bool, outFile string, noColor bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		fmt.Fprintln(os.Stderr, "URL tidak valid:", raw)
		return
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""

	quiet := asJSON || outFile != ""
	color := !noColor && !quiet

	if !quiet {
		banner(color)
		fmt.Printf("%s target  %s\n", dim("»", color), u.String())
		fmt.Printf("%s mode    scan URL pasif (GET saja) · depth=%d\n\n", dim("»", color), cfg.depth)
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.insecure}}
	cl := &http.Client{
		Transport:     tr,
		Timeout:       cfg.timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	conc := cfg.concurrency
	if conc <= 0 {
		conc = 20
	}
	s := &urlScanner{
		cl: cl, cfg: cfg, base: u,
		seen: map[string]bool{},
		sem:  make(chan struct{}, conc),
	}
	rep := s.run()

	if outFile != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(outFile, b, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "gagal menulis file:", err)
			return
		}
		fmt.Println("laporan JSON ditulis ke", outFile)
		return
	}
	if asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		return
	}
	printURLReport(rep, color)
	if len(rep.Hits) > 0 || len(rep.Weaknesses) > 0 {
		os.Exit(1)
	}
}

func printURLReport(r URLReport, color bool) {
	fmt.Printf("%s  %s\n", bold("HOST", color),
		dim(fmt.Sprintf("%d request · %dms", r.Requests, r.DurationMS), color))
	fmt.Printf("  target  %s\n", r.Target)
	if len(r.IPs) > 0 {
		fmt.Printf("  IP      %s\n", cyan(strings.Join(r.IPs, ", "), color))
	}
	if len(r.ReverseDNS) > 0 {
		fmt.Printf("  host    %s\n", dim(strings.Join(r.ReverseDNS, ", "), color))
	}
	if r.Server != "" {
		fmt.Printf("  server  %s\n", r.Server)
	}
	if len(r.Tech) > 0 {
		fmt.Printf("  teknologi %s\n", strings.Join(r.Tech, ", "))
	}

	if len(r.Weaknesses) > 0 {
		fmt.Printf("\n%s\n", bold("KELEMAHAN KEAMANAN", color))
		for _, w := range r.Weaknesses {
			fmt.Printf("  %s %s\n", sevTag(w.Severity, color), w.Title)
			if w.Detail != "" {
				fmt.Printf("      %s\n", dim(w.Detail, color))
			}
			if w.Fix != "" {
				fmt.Printf("      %s %s\n", cyan("fix:", color), w.Fix)
			}
		}
	}

	if len(r.Hits) > 0 {
		fmt.Printf("\n%s\n", bold("TEMUAN HALAMAN", color))
		for _, h := range r.Hits {
			tag := cyan("["+h.Kind+"]", color)
			switch h.Kind {
			case "webshell":
				tag = red("[webshell?]", color)
			case "uploader":
				tag = yellow("[uploader]", color)
			}
			fmt.Printf("  %s %s\n", tag, h.URL)
			if h.Note != "" {
				fmt.Printf("      %s\n", dim(h.Note, color))
			}
		}
	}

	fmt.Printf("\n%s (%d)\n", bold("PATH 200", color), len(r.Paths))
	for _, p := range r.Paths {
		meta := fmt.Sprintf("%dB", p.Length)
		if p.Title != "" {
			meta += " · " + p.Title
		}
		fmt.Printf("  %s  %-40s %s %s\n", green("200", color), p.Path, dim("["+p.Source+"]", color), dim(meta, color))
	}
	if len(r.Paths) == 0 {
		fmt.Println("  " + dim("tidak ada path 200 yang ditemukan dari penelusuran", color))
	}
	fmt.Println()
}

func sevTag(sev string, color bool) string {
	switch sev {
	case "TINGGI":
		return red("[TINGGI]", color)
	case "SEDANG":
		return yellow("[SEDANG]", color)
	default:
		return cyan("[RENDAH]", color)
	}
}

func (s *urlScanner) run() URLReport {
	start := time.Now()
	rep := URLReport{Target: s.base.String()}

	// host info
	host := s.base.Hostname()
	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			rep.IPs = append(rep.IPs, ip.String())
		}
		if len(ips) > 0 {
			if names, err := net.LookupAddr(ips[0].String()); err == nil {
				for _, n := range names {
					rep.ReverseDNS = append(rep.ReverseDNS, strings.TrimSuffix(n, "."))
				}
			}
		}
	}

	root := s.fetch("/")
	if root != nil {
		rep.Server = root.headers.Get("Server")
		rep.Tech = s.fingerprint(root)
		s.auditResp(root)
		s.inspect("/", root)
	}

	// seed discovery (wordless)
	seed := map[string]string{}
	addSeed := func(ps []string, src string) {
		for _, p := range ps {
			if _, ok := seed[p]; !ok {
				seed[p] = src
			}
		}
	}
	if root != nil {
		addSeed(s.linksFromHTML(root.body), "html")
		for _, js := range s.jsURLs(root.body) {
			if r := s.fetch(js); r != nil {
				addSeed(s.pathsFromJS(r.body), "js")
			}
		}
	}
	if r := s.fetch("/robots.txt"); r != nil && r.status == 200 {
		p, sm := s.fromRobots(r.body)
		addSeed(p, "robots")
		for _, m := range sm {
			if pp := s.samePath(m); pp != "" {
				if rr := s.fetch(pp); rr != nil {
					addSeed(s.fromSitemap(rr.body), "sitemap")
				}
			}
		}
	}
	if r := s.fetch("/sitemap.xml"); r != nil && r.status == 200 {
		addSeed(s.fromSitemap(r.body), "sitemap")
	}

	// probe + recurse, keep only 200
	frontier := make([]string, 0, len(seed))
	srcOf := map[string]string{}
	for p, src := range seed {
		frontier = append(frontier, p)
		srcOf[p] = src
	}
	for round := 0; round <= s.cfg.depth; round++ {
		if len(frontier) == 0 {
			break
		}
		next := map[string]bool{}
		var wg sync.WaitGroup
		var lmu sync.Mutex
		var htmlPages []struct {
			path string
			r    *uResp
		}
		for _, p := range frontier {
			if !s.mark(p) {
				continue
			}
			wg.Add(1)
			s.sem <- struct{}{}
			go func(path string) {
				defer wg.Done()
				defer func() { <-s.sem }()
				r := s.fetch(path)
				if r == nil || r.status != 200 {
					return
				}
				title := ""
				if isHTMLResp(r) {
					title = s.title(r.body)
				}
				s.mu.Lock()
				s.paths = append(s.paths, URLPath{Path: path, URL: s.abs(path), Length: len(r.body), Title: title, Source: srcOf[path]})
				s.mu.Unlock()
				s.inspect(path, r)
				if isHTMLResp(r) {
					lmu.Lock()
					htmlPages = append(htmlPages, struct {
						path string
						r    *uResp
					}{path, r})
					lmu.Unlock()
				}
			}(p)
		}
		wg.Wait()
		for _, hp := range htmlPages {
			for _, np := range s.linksFromHTML(hp.r.body) {
				if !s.isSeen(np) {
					next[np] = true
					srcOf[np] = "recursive"
				}
			}
		}
		frontier = frontier[:0]
		for p := range next {
			frontier = append(frontier, p)
		}
	}

	s.auditTransport()

	sort.Slice(s.paths, func(i, j int) bool { return s.paths[i].Path < s.paths[j].Path })
	rep.Paths = s.paths
	rep.Hits = s.hits
	rep.Weaknesses = sortURLWeak(s.weaks)
	rep.Requests = s.req
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep
}

// ---- http ----

func (s *urlScanner) fetch(path string) *uResp {
	s.mu.Lock()
	if s.req >= 3000 {
		s.mu.Unlock()
		return nil
	}
	s.req++
	s.mu.Unlock()

	req, err := http.NewRequest(http.MethodGet, s.abs(path), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", s.cfg.ua)
	req.Header.Set("Accept", "*/*")
	resp, err := s.cl.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return &uResp{status: resp.StatusCode, headers: resp.Header, body: body, ct: resp.Header.Get("Content-Type")}
}

func (s *urlScanner) abs(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return s.base.Scheme + "://" + s.base.Host + path
}

func isHTMLResp(r *uResp) bool { return strings.Contains(strings.ToLower(r.ct), "html") }

func (s *urlScanner) mark(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[p] {
		return false
	}
	s.seen[p] = true
	return true
}
func (s *urlScanner) isSeen(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[p]
}

// ---- extraction ----

func (s *urlScanner) samePath(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	low := strings.ToLower(ref)
	for _, bad := range []string{"data:", "mailto:", "javascript:", "tel:", "#"} {
		if strings.HasPrefix(low, bad) {
			return ""
		}
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := s.base.ResolveReference(u)
	if abs.Host != s.base.Host {
		return ""
	}
	p := abs.EscapedPath()
	if p == "" {
		p = "/"
	}
	if abs.RawQuery != "" {
		p += "?" + abs.RawQuery
	}
	return p
}

func (s *urlScanner) linksFromHTML(body []byte) []string {
	var out []string
	for _, m := range uHref.FindAllSubmatch(body, -1) {
		if p := s.samePath(string(m[1])); p != "" {
			out = append(out, p)
		}
	}
	return out
}
func (s *urlScanner) pathsFromJS(body []byte) []string {
	var out []string
	for _, m := range uJSPath.FindAllSubmatch(body, -1) {
		if p := s.samePath(string(m[1])); p != "" {
			out = append(out, p)
		}
	}
	return out
}
func (s *urlScanner) jsURLs(body []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range uHref.FindAllSubmatch(body, -1) {
		ref := string(m[1])
		if !strings.Contains(strings.ToLower(ref), ".js") {
			continue
		}
		if p := s.samePath(ref); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
			if len(out) >= 25 {
				break
			}
		}
	}
	return out
}
func (s *urlScanner) fromRobots(body []byte) (paths, sitemaps []string) {
	for _, m := range uRobots.FindAllSubmatch(body, -1) {
		raw := strings.TrimSpace(string(m[1]))
		if raw == "" || raw == "/" {
			continue
		}
		if p := s.samePath(raw); p != "" {
			paths = append(paths, p)
		}
	}
	for _, line := range strings.Split(string(body), "\n") {
		if i := strings.Index(strings.ToLower(line), "sitemap:"); i >= 0 {
			sitemaps = append(sitemaps, strings.TrimSpace(line[i+len("sitemap:"):]))
		}
	}
	return
}
func (s *urlScanner) fromSitemap(body []byte) []string {
	var out []string
	for _, m := range uLoc.FindAllSubmatch(body, -1) {
		if p := s.samePath(string(m[1])); p != "" {
			out = append(out, p)
		}
	}
	return out
}
func (s *urlScanner) title(body []byte) string {
	m := uTitle.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := strings.Join(strings.Fields(string(m[1])), " ")
	if len(t) > 70 {
		t = t[:70] + "…"
	}
	return t
}

// ---- classification & audit ----

func (s *urlScanner) inspect(path string, r *uResp) {
	if !isHTMLResp(r) && !uShell.Match(r.body) {
		return
	}
	if uShell.Match(r.body) {
		s.addHit(path, "webshell", "halaman cocok dengan tampilan webshell yang dikenal — periksa manual")
	}
	if uUpload.Match(r.body) {
		s.addHit(path, "uploader", "ada form upload file (input file / multipart)")
	}
	if uLogin.Match(r.body) {
		s.addHit(path, "login", "halaman memuat form login")
	}
	if uDirList.Match(r.body) {
		s.addWeak(URLWeak{"SEDANG", "Directory listing menyala di " + path, "",
			"Matikan auto-index: `autoindex off;` (Nginx) / `Options -Indexes` (Apache)."})
	}
}

func (s *urlScanner) fingerprint(r *uResp) []string {
	set := map[string]bool{}
	add := func(x string) { set[x] = true }
	if v := r.headers.Get("X-Powered-By"); v != "" {
		add("X-Powered-By: " + v)
	}
	cookies := strings.ToLower(strings.Join(r.headers["Set-Cookie"], " "))
	for frag, tech := range map[string]string{
		"laravel_session": "Laravel", "phpsessid": "PHP", "connect.sid": "Express/Node",
		"jsessionid": "Java", "csrftoken": "Django", "ci_session": "CodeIgniter", "wordpress_": "WordPress",
	} {
		if strings.Contains(cookies, frag) {
			add(tech)
		}
	}
	body := strings.ToLower(string(r.body))
	for frag, tech := range map[string]string{
		"/wp-content/": "WordPress", "__next_data__": "Next.js", "data-reactroot": "React",
		"ng-version": "Angular", "/_nuxt/": "Nuxt.js", "drupal-settings-json": "Drupal",
	} {
		if strings.Contains(body, frag) {
			add(tech)
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *urlScanner) auditResp(r *uResp) {
	for _, h := range uSecHeaders {
		if r.headers.Get(h.key) == "" {
			s.addWeak(URLWeak{h.sev, "Header keamanan hilang: " + h.label, "", h.fix})
		}
	}
	for _, raw := range r.headers["Set-Cookie"] {
		name := raw
		if i := strings.IndexByte(raw, '='); i >= 0 {
			name = raw[:i]
		}
		low := strings.ToLower(raw)
		var miss []string
		if !strings.Contains(low, "secure") {
			miss = append(miss, "Secure")
		}
		if !strings.Contains(low, "httponly") {
			miss = append(miss, "HttpOnly")
		}
		if !strings.Contains(low, "samesite") {
			miss = append(miss, "SameSite")
		}
		if len(miss) > 0 {
			s.addWeak(URLWeak{"SEDANG", "Cookie `" + strings.TrimSpace(name) + "` kurang atribut: " + strings.Join(miss, ", "), "",
				"Tambahkan `Secure; HttpOnly; SameSite=Lax`, terutama cookie sesi."})
		}
	}
	if v := r.headers.Get("Server"); v != "" && uHasVer.MatchString(v) {
		s.addWeak(URLWeak{"RENDAH", "Versi server terekspos di header", "Server: " + v,
			"Sembunyikan versi: `server_tokens off;` (Nginx) / `ServerTokens Prod` (Apache)."})
	}
	if v := r.headers.Get("X-Powered-By"); v != "" {
		s.addWeak(URLWeak{"RENDAH", "Teknologi backend terekspos (X-Powered-By)", "X-Powered-By: " + v,
			"Matikan: `expose_php = Off` di php.ini atau hapus header di proxy."})
	}
}

func (s *urlScanner) auditTransport() {
	host := s.base.Host
	if s.base.Scheme == "https" {
		hp := host
		if !strings.Contains(hp, ":") {
			hp += ":443"
		}
		d := &net.Dialer{Timeout: 8 * time.Second}
		if conn, err := tls.DialWithDialer(d, "tcp", hp, &tls.Config{InsecureSkipVerify: true}); err == nil {
			cs := conn.ConnectionState()
			conn.Close()
			if len(cs.PeerCertificates) > 0 {
				cert := cs.PeerCertificates[0]
				days := int(time.Until(cert.NotAfter).Hours() / 24)
				if days < 0 {
					s.addWeak(URLWeak{"TINGGI", "Sertifikat TLS sudah kedaluwarsa", "kedaluwarsa " + cert.NotAfter.Format("2006-01-02"), "Perbarui sertifikat segera."})
				} else if days < 14 {
					s.addWeak(URLWeak{"SEDANG", fmt.Sprintf("Sertifikat TLS hampir kedaluwarsa (%d hari lagi)", days), "", "Perbarui sebelum habis; otomatiskan dengan certbot."})
				}
			}
			if cs.Version < tls.VersionTLS12 {
				s.addWeak(URLWeak{"SEDANG", "Server menerima TLS lama (< 1.2)", "", "Hanya izinkan TLS 1.2 dan 1.3."})
			}
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	if req != nil {
		req.Header.Set("User-Agent", s.cfg.ua)
		if resp, err := s.cl.Do(req); err == nil {
			loc := strings.ToLower(resp.Header.Get("Location"))
			resp.Body.Close()
			if !(resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(loc, "https://")) {
				s.addWeak(URLWeak{"SEDANG", "HTTP tidak dialihkan ke HTTPS",
					fmt.Sprintf("http://%s/ menjawab %d tanpa redirect https", host, resp.StatusCode),
					"Paksa redirect 301 ke HTTPS, aktifkan HSTS."})
			}
		}
	}
}

func (s *urlScanner) addHit(path, kind, note string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.hits {
		if h.Path == path && h.Kind == kind {
			return
		}
	}
	s.hits = append(s.hits, URLHit{Path: path, URL: s.abs(path), Kind: kind, Note: note})
}
func (s *urlScanner) addWeak(w URLWeak) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.weaks {
		if e.Title == w.Title {
			return
		}
	}
	s.weaks = append(s.weaks, w)
}

func sortURLWeak(ws []URLWeak) []URLWeak {
	rank := map[string]int{"TINGGI": 0, "SEDANG": 1, "RENDAH": 2}
	out := append([]URLWeak(nil), ws...)
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}
