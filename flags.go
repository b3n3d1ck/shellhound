package main

import (
	"flag"
	"strconv"
)

// Thin wrappers over the standard flag package, so main.go reads cleanly.

func flagString(name, def, usage string) *string         { return flag.String(name, def, usage) }
func flagBool(name string, def bool, usage string) *bool { return flag.Bool(name, def, usage) }
func flagInt(name string, def int, usage string) *int    { return flag.Int(name, def, usage) }

func parseFlags(usage func()) {
	flag.Usage = usage
	flag.Parse()
}

func positional() []string { return flag.Args() }
func printDefaults()       { flag.PrintDefaults() }

func itoa(n int) string { return strconv.Itoa(n) }
