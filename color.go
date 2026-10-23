package main

import "fmt"

// Minimal ANSI color helpers. Each takes a `color bool` so output stays plain
// when piped to a file or when --no-color is set.

const (
	cReset  = "\x1b[0m"
	cDim    = "\x1b[2m"
	cBold   = "\x1b[1m"
	cRed    = "\x1b[31m"
	cGreen  = "\x1b[32m"
	cYellow = "\x1b[33m"
	cCyan   = "\x1b[36m"
	cGray   = "\x1b[90m"
)

func paint(s, code string, on bool) string {
	if !on {
		return s
	}
	return code + s + cReset
}

func dim(s string, on bool) string    { return paint(s, cDim, on) }
func bold(s string, on bool) string   { return paint(s, cBold, on) }
func red(s string, on bool) string    { return paint(s, cRed, on) }
func green(s string, on bool) string  { return paint(s, cGreen, on) }
func yellow(s string, on bool) string { return paint(s, cYellow, on) }
func cyan(s string, on bool) string   { return paint(s, cCyan, on) }
func gray(s string, on bool) string   { return paint(s, cGray, on) }

func banner(on bool) {
	art := "       _          _ _ _                           _\n   ___| |__   ___| | | |__   ___  _   _ _ __   __| |\n  / __| '_ \\ / _ \\ | | '_ \\ / _ \\| | | | '_ \\ / _` |\n  \\__ \\ | | |  __/ | | | | | (_) | |_| | | | | (_| |\n  |___/_| |_|\\___|_|_|_| |_|\\___/ \\__,_|_| |_|\\__,_|"
	fmt.Println(green(art, on))
	fmt.Println(dim("  pemburu webshell & backdoor - pindai filesystem, cocokkan signature\n", on))
}
