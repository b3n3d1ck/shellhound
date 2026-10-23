package main

import "regexp"

// kind groups indicators so the report can explain itself.
type kind int

const (
	kShell  kind = iota // distinctive string from a known webshell family
	kSink               // dangerous function that can run code or commands
	kObfus              // obfuscation / packing that hides what the code does
	kUpload             // file-upload capability (often how a shell lands)
	kInput              // user-controlled input reaching a sink
)

func (k kind) label() string {
	switch k {
	case kShell:
		return "signature webshell dikenal"
	case kSink:
		return "fungsi eksekusi berbahaya"
	case kObfus:
		return "kode terobfuscasi / dikemas"
	case kUpload:
		return "kemampuan upload file"
	case kInput:
		return "input user masuk ke fungsi berbahaya"
	}
	return "lainnya"
}

// indicator is one thing we look for. Either lit (a literal substring, matched
// case-insensitively) or re (a compiled regex) is set, not both.
type indicator struct {
	name   string
	kind   kind
	weight int
	lit    string
	re     *regexp.Regexp
}

func lit(name string, k kind, w int, s string) indicator {
	return indicator{name: name, kind: k, weight: w, lit: s}
}
func rx(name string, k kind, w int, pat string) indicator {
	return indicator{name: name, kind: k, weight: w, re: regexp.MustCompile(pat)}
}

// Named webshell families. These strings show up in the real tools and rarely
// in legitimate code. A hit here is a strong signal on its own.
var shellStrings = []string{
	"c99shell", "c99madshell", "r57shell", "b374k", "wsoshell", "filesman",
	"indoxploit", "idx_tgmedia", "alfa team", "alfashell", "alfav", "k2ll33d",
	"madspot", "mister spy", "ani-shell", "priv8", "priv-8", "symlink bypass",
	"marijuana shell", "crystal shell", "sadrazam", "0byt3m1n1", "zehir",
	"mini shell", "p0wny", "p0wny@shell", "weevely", "chinese caidao",
	"antichat shell", "gazavat", "shell by", "uploaded by", "bypass safe mode",
	"adminer.php", "webadmin.php",
}

// indicators is the full detection set. Weights are additive; see classify().
var indicators = func() []indicator {
	var ix []indicator
	for _, s := range shellStrings {
		ix = append(ix, lit(s, kShell, 55, s))
	}
	ix = append(ix,
		// --- obfuscated execution: the classic packed-shell shape ---
		rx("eval(base64_decode(...))", kObfus, 60, `(?i)\beval\s*\(\s*(?:gzinflate|gzuncompress|str_rot13|base64_decode|convert_uu|hex2bin)\s*\(`),
		rx("assert(base64_decode(...))", kObfus, 60, `(?i)\bassert\s*\(\s*(?:gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(`),
		rx("preg_replace /e (eksekusi)", kSink, 55, `(?i)\bpreg_replace\s*\([^;]{0,160}?/[a-zA-Z]*e[a-zA-Z]*['"]`),
		rx("create_function", kSink, 35, `(?i)\bcreate_function\s*\(`),
		rx("rantai decode berlapis", kObfus, 35, `(?i)(?:gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(\s*(?:gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(`),

		// --- direct code / command execution ---
		rx("eval(", kSink, 30, `(?i)\beval\s*\(`),
		rx("assert(", kSink, 25, `(?i)\bassert\s*\(`),
		rx("system/exec/shell_exec/passthru", kSink, 25, `(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(`),
		rx("eksekusi via backtick", kSink, 25, "`[^`\n]*\\$"),
		rx("call_user_func", kSink, 15, `(?i)\bcall_user_func(?:_array)?\s*\(`),
		rx("variable function $x(", kSink, 20, `\$[a-zA-Z_]\w*\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)`),
		rx("variable variable $$", kSink, 12, `\$\$[a-zA-Z_]\w*`),

		// --- obfuscation heuristics ---
		rx("blob base64 panjang", kObfus, 18, `['"][A-Za-z0-9+/]{260,}={0,2}['"]`),
		rx("rangkaian chr()", kObfus, 20, `(?:\bchr\s*\(\s*\d+\s*\)\s*\.\s*){6,}`),
		rx("deret escape heksa", kObfus, 18, `(?:\\x[0-9A-Fa-f]{2}){12,}`),
		rx("gzinflate/str_rot13", kObfus, 15, `(?i)\b(?:gzinflate|gzuncompress|str_rot13)\s*\(`),
		rx("FilesMan/WSO auth cookie", kShell, 40, `(?i)\$(?:auth_pass|default_action|default_use_ajax)\b`),

		// --- file upload (how a shell usually arrives) ---
		rx("move_uploaded_file", kUpload, 20, `(?i)\bmove_uploaded_file\s*\(`),
		rx("tulis file dari input", kUpload, 25, `(?i)\bf(?:ile_put_contents|write|puts)\s*\([^)]*\$_(?:GET|POST|REQUEST)`),
		rx("$_FILES handler", kUpload, 10, `\$_FILES\b`),

		// --- input reaching a sink (set as a bonus in classify) ---
		rx("superglobal input", kInput, 0, `\$_(?:GET|POST|REQUEST|COOKIE)\b`),
	)
	return ix
}()

// maskLine hides long base64/hex blobs and obvious secrets so the report never
// prints a working payload or a live credential.
var (
	reBlob   = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	reHexRun = regexp.MustCompile(`(?:\\x[0-9A-Fa-f]{2}){8,}`)
	reSecret = regexp.MustCompile(`(?i)(pass(?:word|wd)?|secret|api[_-]?key|token|auth_pass)\s*[=:]\s*['"]?[^'"\s,;)]{3,}`)
)

func maskLine(s string) string {
	s = reBlob.ReplaceAllString(s, "«blob-base64-disembunyikan»")
	s = reHexRun.ReplaceAllString(s, "«hex-disembunyikan»")
	s = reSecret.ReplaceAllStringFunc(s, func(m string) string {
		// keep the key name, drop the value
		for i := 0; i < len(m); i++ {
			if m[i] == '=' || m[i] == ':' {
				return m[:i+1] + " «disensor»"
			}
		}
		return "«disensor»"
	})
	if len(s) > 200 {
		s = s[:200] + " …"
	}
	return s
}
