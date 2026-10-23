// shellhound — filesystem webshell & backdoor scanner.
// Run it on a server you own or are explicitly authorized to inspect.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const version = "0.1.0"

func main() {
	var (
		extCSV   = flagString("ext", "php,php3,php4,php5,php7,phtml,pht,phar,inc", "ekstensi yang diperiksa (dipisah koma)")
		allExt   = flagBool("all-ext", false, "periksa SEMUA file teks, bukan cuma ekstensi PHP")
		minScore = flagInt("min", 25, "skor minimum untuk dilaporkan (makin tinggi makin ketat)")
		maxMB    = flagInt("max-size", 3, "lewati file lebih besar dari sekian MB")
		base     = flagString("base", "", "URL dasar untuk memetakan path file -> link (mis. https://situsku.com)")
		skipCSV  = flagString("skip", ".git,node_modules,.svn,.hg", "nama folder yang dilewati (dipisah koma)")
		noSkip   = flagBool("no-skip", false, "jangan lewati folder apa pun")
		conc     = flagInt("c", 0, "jumlah worker paralel (0 = otomatis)")
		asJSON   = flagBool("json", false, "keluarkan JSON")
		outFile  = flagString("o", "", "tulis laporan JSON ke file")
		noColor  = flagBool("no-color", false, "matikan warna")
		showVer  = flagBool("version", false, "cetak versi lalu keluar")
		// mode URL (kalau argumen berupa link)
		depth    = flagInt("depth", 2, "[mode URL] kedalaman penelusuran link")
		timeout  = flagInt("timeout", 10, "[mode URL] timeout per request (detik)")
		insecure = flagBool("insecure", false, "[mode URL] lewati verifikasi sertifikat TLS")
		ua       = flagString("ua", "shellhound/"+version, "[mode URL] User-Agent")
	)
	parseFlags(usage)

	if *showVer {
		fmt.Println("shellhound " + version)
		return
	}
	args := positional()
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	root := args[0]

	// --- mode URL: input berupa link, bukan folder ---
	if isURL(root) {
		runURLScan(root, urlConfig{
			timeout:     time.Duration(*timeout) * time.Second,
			insecure:    *insecure,
			ua:          *ua,
			concurrency: *conc,
			depth:       *depth,
		}, *asJSON, *outFile, *noColor)
		return
	}

	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "bukan folder yang bisa dibaca: %s\n", root)
		os.Exit(2)
	}

	exts := map[string]bool{}
	for _, e := range strings.Split(*extCSV, ",") {
		if e = strings.TrimSpace(strings.TrimPrefix(e, ".")); e != "" {
			exts[strings.ToLower(e)] = true
		}
	}
	skip := map[string]bool{}
	if !*noSkip {
		for _, d := range strings.Split(*skipCSV, ",") {
			if d = strings.TrimSpace(d); d != "" {
				skip[d] = true
			}
		}
	}

	quiet := *asJSON || *outFile != ""
	color := !*noColor && !quiet

	if !quiet {
		banner(color)
		fmt.Printf("%s target  %s\n", dim("»", color), root)
		fmt.Printf("%s mode    baca filesystem (read-only) · min-skor=%d\n\n", dim("»", color), *minScore)
	}

	start := time.Now()
	sc := newScanner(config{
		root:        root,
		exts:        exts,
		scanAllExt:  *allExt,
		skipDirs:    skip,
		minScore:    *minScore,
		maxSize:     int64(*maxMB) * 1024 * 1024,
		urlBase:     *base,
		concurrency: *conc,
	})
	rep := sc.Run()
	rep.DurationMS = time.Since(start).Milliseconds()

	if *outFile != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*outFile, b, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "gagal menulis file:", err)
			os.Exit(1)
		}
		fmt.Println("laporan JSON ditulis ke", *outFile)
		return
	}
	if *asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		return
	}
	printReport(rep, color)

	if len(rep.Findings) > 0 {
		os.Exit(1) // non-zero so CI / cron can act on a hit
	}
}

func printReport(r Report, color bool) {
	fmt.Printf("%s  %s\n",
		bold("RINGKASAN", color),
		dim(fmt.Sprintf("%d file ditelusuri · %d dibaca · %dms", r.FilesWalked, r.FilesRead, r.DurationMS), color))

	if len(r.Findings) == 0 {
		fmt.Println("\n  " + green("bersih — tidak ada yang cocok dengan signature.", color))
		fmt.Println("  " + dim("catatan: skor bersih bukan jaminan 100%. Shell yang sangat baru bisa lolos.", color))
		return
	}

	fmt.Printf("\n%s %s\n", bold("DITEMUKAN", color), dim(fmt.Sprintf("(%d file)", len(r.Findings)), color))
	for _, f := range r.Findings {
		fmt.Println()
		fmt.Printf("  %s  %s\n", verdictTag(f.Verdict, f.Score, color), bold(f.Path, color))
		if f.URL != "" {
			fmt.Printf("      link   %s\n", cyan(f.URL, color))
		}
		fmt.Printf("      ukuran %dB · skor %d\n", f.Size, f.Score)
		shown := f.Hits
		if len(shown) > 6 {
			shown = shown[:6]
		}
		for _, h := range shown {
			loc := ""
			if h.Line > 0 {
				loc = fmt.Sprintf("baris %d: ", h.Line)
			}
			fmt.Printf("      %s %s %s\n", yellow("•", color), h.Name, dim("(+"+itoa(h.Weight)+")", color))
			if h.Snippet != "" {
				fmt.Printf("          %s%s\n", dim(loc, color), gray(h.Snippet, color))
			}
		}
		if len(f.Hits) > len(shown) {
			fmt.Printf("      %s\n", dim(fmt.Sprintf("… +%d indikator lain", len(f.Hits)-len(shown)), color))
		}
	}

	remediation(color)
}

func verdictTag(v string, score int, color bool) string {
	switch {
	case score >= 70:
		return red("["+v+"]", color)
	case score >= 45:
		return yellow("["+v+"]", color)
	default:
		return cyan("["+v+"]", color)
	}
}

func remediation(color bool) {
	fmt.Printf("\n%s\n", bold("LANGKAH PENANGANAN", color))
	steps := []string{
		"Jangan buka file mencurigakan lewat browser. Memanggil URL-nya sama saja menjalankan shell-nya.",
		"Isolasi dulu, jangan langsung hapus: salin file ke luar web root (misalnya `mv shell.php /root/karantina/`) biar barang buktinya aman buat ditelusuri.",
		"Cek log akses server (`access.log`) untuk IP dan waktu file itu dipanggil. Dari situ ketahuan titik masuk dan file lain yang mungkin kena.",
		"Cari file lain yang dimodifikasi di sekitar waktu yang sama: `find /var/www -type f -mmin -1440 -name '*.php'`.",
		"Setelah yakin, ganti semua kredensial yang ada di server: DB, API key, panel admin, SSH.",
	}
	for i, s := range steps {
		fmt.Printf("  %s %s\n", cyan(itoa(i+1)+".", color), s)
	}

	fmt.Printf("\n%s\n", bold("CARA MENUTUP CELAHNYA", color))
	hard := []string{
		"Matikan eksekusi PHP di folder upload. Di Nginx: blok `location ~* /uploads/.*\\.php$ { deny all; }`. Di Apache lewat .htaccess: `php_admin_flag engine off`.",
		"Batasi fungsi berbahaya di php.ini: `disable_functions = exec,passthru,shell_exec,system,proc_open,popen,assert` (sesuaikan dengan kebutuhan aplikasi).",
		"Pasang `open_basedir` supaya skrip tidak bisa membaca di luar direktori aplikasi.",
		"Perbarui CMS, plugin, dan tema. Mayoritas shell masuk lewat plugin/tema usang atau form upload yang tidak memvalidasi tipe file.",
		"Validasi upload berdasarkan isi (MIME + magic bytes), bukan cuma ekstensi, dan simpan file di luar web root bila bisa.",
		"Jadwalkan scan berkala: taruh shellhound di cron harian, atau lengkapi dengan maldet/ClamAV.",
	}
	for _, s := range hard {
		fmt.Printf("  %s %s\n", cyan("›", color), s)
	}
	fmt.Println()
}

func usage() {
	fmt.Fprintf(os.Stderr, `shellhound %s — pemburu webshell & backdoor

Dua mode, dipilih otomatis dari argumen:

  shellhound <folder>   mode FILESYSTEM — baca web root di disk, cocokkan tiap
                        file PHP dengan signature shell. Paling ampuh.
  shellhound <url>      mode URL — telusuri situs secara pasif dari link-nya
                        (tanpa wordlist), laporkan hanya path 200, kenali
                        halaman login/uploader/webshell, info IP/host/server,
                        dan daftar kelemahan + cara fix. Hanya GET.

  shellhound /var/www/html
  shellhound -base https://situsku.com -json -o lapor.json /var/www/html
  shellhound https://situsku.com
  shellhound -depth 3 https://situsku.com

Opsi:
`, version)
	printDefaults()
	fmt.Fprintln(os.Stderr, `
PENTING: jalankan hanya pada server yang kamu miliki atau yang kamu
diberi izin tertulis untuk diperiksa.`)
}
