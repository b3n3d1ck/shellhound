package main

import (
	"strings"
	"testing"
)

func TestClassifyFlagsPackedShell(t *testing.T) {
	body := []byte(`<?php eval(gzinflate(base64_decode($_POST['x']))); ?>`)
	hits, score := classify(body)
	if score < 70 {
		t.Fatalf("packed shell should score high, got %d", score)
	}
	if len(hits) == 0 {
		t.Fatal("expected indicators, got none")
	}
}

func TestClassifyFlagsNamedShell(t *testing.T) {
	body := []byte(`<?php /* c99shell */ $x=1;`)
	_, score := classify(body)
	if score < 45 {
		t.Fatalf("named shell should be suspicious, got %d", score)
	}
}

func TestClassifyInputBonus(t *testing.T) {
	withInput := []byte(`<?php system($_GET['c']);`)
	noInput := []byte(`<?php system("ls -la");`)
	_, a := classify(withInput)
	_, b := classify(noInput)
	if a <= b {
		t.Fatalf("user input should raise the score: with=%d without=%d", a, b)
	}
}

func TestClassifyIgnoresBenign(t *testing.T) {
	body := []byte(`<?php
$title = "Home";
echo htmlspecialchars($title);
$rows = $pdo->query("SELECT id FROM t")->fetchAll();
`)
	_, score := classify(body)
	if score >= 25 {
		t.Fatalf("benign code should stay below report threshold, got %d", score)
	}
}

func TestMaskLineHidesSecretsAndBlobs(t *testing.T) {
	in := `$auth_pass = "e10adc3949ba59abbe56e057f20f883e"; $p="QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"`
	out := maskLine(in)
	if strings.Contains(out, "e10adc3949ba59abbe") {
		t.Fatalf("password value leaked: %s", out)
	}
	if strings.Contains(out, "QUJDREVGR0hJSkt") {
		t.Fatalf("base64 blob leaked: %s", out)
	}
}

func TestLineAt(t *testing.T) {
	b := []byte("a\nb\nTARGET\nd")
	idx := strings.Index(string(b), "TARGET")
	line, text := lineAt(b, idx)
	if line != 3 || text != "TARGET" {
		t.Fatalf("got line=%d text=%q", line, text)
	}
}
