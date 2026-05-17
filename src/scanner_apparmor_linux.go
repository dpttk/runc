package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// apparmorAuditMarkerEnd closes the rule block opened by
// apparmorAuditMarkerBegin (declared next to its consumer in
// scanner_finalize_linux.go). The two markers wrap the body of the
// rules the audit collector wrote so that re-running the scan
// replaces the block in place rather than appending duplicate copies.
const apparmorAuditMarkerEnd = "# --- END runc-scan audit-collected rules ---"

// apparmorDeniedLineRegexp matches a kernel/audit log line that
// reports an AppArmor denial. AppArmor formats denials roughly as:
//
//	apparmor="DENIED" operation="open" profile="runc_scan_X" name="/etc/passwd" pid=1 comm="cat" requested_mask="r" denied_mask="r"
//
// The bare-value form (apparmor=DENIED, without quotes) appears in
// some dmesg captures; both are accepted.
var apparmorDeniedLineRegexp = regexp.MustCompile(`apparmor="?DENIED"?`)

// apparmorKeyValueRegexp pulls key="value" or key=value tokens out of
// an audit line. AppArmor's audit format is space-separated; values
// can be quoted (most common) or hex-encoded (rare on file paths,
// which we then skip).
var apparmorKeyValueRegexp = regexp.MustCompile(`(\w+)=("([^"]*)"|(\S+))`)

// appArmorDenialRecord is the structured form of one
// apparmor="DENIED" line. Only fields the rule generator looks at
// are decoded; the rest of the audit metadata is dropped.
type appArmorDenialRecord struct {
	Operation     string
	Profile       string
	Name          string
	Target        string
	RequestedMask string
	DeniedMask    string
	Capname       string
}

// parseApparmorDenials reads audit / journal output and returns the
// denial records that target the given profile. Lines that do not
// look like AppArmor denials, or denials for other profiles, are
// silently dropped.
func parseApparmorDenials(r io.Reader, profileName string) []appArmorDenialRecord {
	out := make([]appArmorDenialRecord, 0)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !apparmorDeniedLineRegexp.MatchString(line) {
			continue
		}
		rec := parseDenialLine(line)
		if rec.Profile != profileName {
			continue
		}
		out = append(out, rec)
	}
	return out
}

func parseDenialLine(line string) appArmorDenialRecord {
	rec := appArmorDenialRecord{}
	for _, m := range apparmorKeyValueRegexp.FindAllStringSubmatch(line, -1) {
		key := m[1]
		val := m[3]
		if val == "" {
			val = m[4]
		}
		switch key {
		case "operation":
			rec.Operation = val
		case "profile":
			rec.Profile = val
		case "name":
			rec.Name = val
		case "target":
			rec.Target = val
		case "requested_mask":
			rec.RequestedMask = val
		case "denied_mask":
			rec.DeniedMask = val
		case "capname":
			rec.Capname = val
		}
	}
	return rec
}

// buildAppArmorRulesFromDenials maps a slice of denial records to a
// deterministic, deduplicated set of profile-body rules ready to
// land between the audit markers. File denials produce path rules,
// capability denials produce `capability NAME,` rules; operations
// the MVP does not understand (mount, signal, ptrace, network ...)
// fall through as `# unhandled:` comments so the operator can finish
// them off manually without losing the evidence.
func buildAppArmorRulesFromDenials(records []appArmorDenialRecord) []string {
	seen := map[string]struct{}{}
	var rules []string
	add := func(rule string) {
		if rule == "" {
			return
		}
		if _, ok := seen[rule]; ok {
			return
		}
		seen[rule] = struct{}{}
		rules = append(rules, rule)
	}
	for _, r := range records {
		switch {
		case r.Operation == "capable" && r.Capname != "":
			add("  capability " + r.Capname + ",")
		case r.Name != "":
			mode := canonicalAppArmorFileMode(r.RequestedMask, r.DeniedMask, r.Operation)
			if mode == "" {
				add(fmt.Sprintf("  # unhandled: operation=%s name=%s", r.Operation, r.Name))
				continue
			}
			add(fmt.Sprintf("  %s %s,", quoteAppArmorPath(r.Name), mode))
		default:
			add(fmt.Sprintf("  # unhandled: operation=%s", r.Operation))
		}
	}
	sort.Strings(rules)
	return rules
}

// canonicalAppArmorFileMode collapses a denied operation and its mask
// down to the single AppArmor mode letter sequence the parser expects
// in a file rule (r, w, rw, ix, ...). Append (a) folds into write;
// unknown letters are dropped.
func canonicalAppArmorFileMode(requested, denied, operation string) string {
	mask := requested
	if mask == "" {
		mask = denied
	}
	if mask == "" {
		switch operation {
		case "open":
			mask = "r"
		case "mknod", "create", "unlink", "rmdir", "rename_src", "rename_dest", "truncate":
			mask = "w"
		case "link":
			mask = "l"
		case "exec":
			mask = "ix"
		default:
			return ""
		}
	}
	want := map[rune]bool{}
	for _, ch := range mask {
		switch ch {
		case 'r':
			want['r'] = true
		case 'w', 'a', 'c', 'd':
			want['w'] = true
		case 'l':
			want['l'] = true
		case 'k':
			want['k'] = true
		case 'm':
			want['m'] = true
		case 'x':
			want['x'] = true
		}
	}
	if len(want) == 0 {
		return ""
	}
	order := []rune{'r', 'w', 'l', 'k', 'm', 'x'}
	var b strings.Builder
	for _, ch := range order {
		if !want[ch] {
			continue
		}
		if ch == 'x' {
			b.WriteString("ix")
			continue
		}
		b.WriteRune(ch)
	}
	return b.String()
}

// quoteAppArmorPath wraps a path in double quotes when it contains a
// space or another character that would otherwise need escaping. Paths
// without unusual characters are returned bare to keep the profile
// readable for human review.
func quoteAppArmorPath(p string) string {
	if p == "" {
		return ""
	}
	if strings.ContainsAny(p, " \t\"\\") {
		return strconv.Quote(p)
	}
	return p
}

// appendAuditRulesToProfile rewrites the on-disk profile so the rules
// produced by the audit collector sit between
// apparmorAuditMarkerBegin/End sentinels inside the profile body. The
// operation is idempotent: a previous block, if any, is replaced.
// When rules is empty no markers are written so finalize keeps the
// profile in complain mode.
func appendAuditRulesToProfile(profilePath string, rules []string) error {
	if len(rules) == 0 {
		return nil
	}
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", profilePath, err)
	}
	stripped := stripExistingAuditBlock(raw)

	closeIdx := findProfileBodyClose(stripped)
	if closeIdx < 0 {
		return fmt.Errorf("profile %s has no closing brace", profilePath)
	}

	var block strings.Builder
	block.WriteString("  " + apparmorAuditMarkerBegin + "\n")
	for _, r := range rules {
		block.WriteString(r)
		block.WriteString("\n")
	}
	block.WriteString("  " + apparmorAuditMarkerEnd + "\n")

	var out bytes.Buffer
	out.Write(stripped[:closeIdx])
	out.WriteString(block.String())
	out.Write(stripped[closeIdx:])

	tmp := profilePath + ".runc-scan.tmp"
	if err := os.WriteFile(tmp, out.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, profilePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", profilePath, err)
	}
	return nil
}

// stripExistingAuditBlock removes a previously-collected rules block
// (and the surrounding indentation/newline) from the profile so we
// can replace it cleanly. Profiles that have never been collected
// against come through unchanged.
func stripExistingAuditBlock(raw []byte) []byte {
	begin := []byte(apparmorAuditMarkerBegin)
	end := []byte(apparmorAuditMarkerEnd)
	bIdx := bytes.Index(raw, begin)
	if bIdx < 0 {
		return raw
	}
	eIdx := bytes.Index(raw[bIdx:], end)
	if eIdx < 0 {
		return raw
	}
	eIdx += bIdx + len(end)
	lineStart := bIdx
	for lineStart > 0 && raw[lineStart-1] != '\n' {
		lineStart--
	}
	lineEnd := eIdx
	if lineEnd < len(raw) && raw[lineEnd] == '\n' {
		lineEnd++
	}
	out := make([]byte, 0, len(raw)-(lineEnd-lineStart))
	out = append(out, raw[:lineStart]...)
	out = append(out, raw[lineEnd:]...)
	return out
}

// findProfileBodyClose returns the byte offset of the final `}` that
// closes the top-level profile block. We rely on it being the last
// non-whitespace character on its own line, which holds for both the
// runc-emitted template and aa-logprof output.
func findProfileBodyClose(raw []byte) int {
	for i := len(raw) - 1; i >= 0; i-- {
		c := raw[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '}':
			return i
		default:
			return -1
		}
	}
	return -1
}

// collectAndAppendAppArmorRules is the entry point called by
// runScanAAUnload. It reads kernel audit output (journalctl -k first,
// dmesg as fallback), filters down to the profile in question and the
// scan's time window, and rewrites the profile in place. All failures
// short of "wrote bad bytes to disk" are downgraded to log lines so
// container teardown is never blocked by a missing tool.
func collectAndAppendAppArmorRules(profilePath, genDir string, logFile io.Writer) error {
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", profilePath, err)
	}
	m := apparmorProfileLineRegexp.FindSubmatch(raw)
	if m == nil {
		return fmt.Errorf("profile %s has no header", profilePath)
	}
	profileName := string(m[1])

	since := readAAStartedAt(genDir)
	audit, source, err := readKernelAudit(since)
	fmt.Fprintf(logFile, "audit source=%s err=%v bytes=%d\n", source, err, len(audit))
	if len(audit) == 0 {
		return nil
	}
	records := parseApparmorDenials(bytes.NewReader(audit), profileName)
	fmt.Fprintf(logFile, "audit denials for %s: %d\n", profileName, len(records))
	if len(records) == 0 {
		return nil
	}
	rules := buildAppArmorRulesFromDenials(records)
	if err := appendAuditRulesToProfile(profilePath, rules); err != nil {
		return err
	}
	fmt.Fprintf(logFile, "audit rules appended: %d\n", len(rules))
	return nil
}

func readAAStartedAt(genDir string) time.Time {
	raw, err := os.ReadFile(filepath.Join(genDir, scanAAStartedAtFile))
	if err != nil {
		return time.Time{}
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// readKernelAudit returns the kernel audit / journal slice that
// covers `since` onwards. It tries journalctl -k first (the default
// systemd shipping target) and falls back to `dmesg --since`-style
// parsing only if journalctl is not on PATH or its output is empty.
// Both paths return the raw bytes verbatim; parsing happens upstream.
func readKernelAudit(since time.Time) ([]byte, string, error) {
	if path, lerr := exec.LookPath("journalctl"); lerr == nil {
		args := []string{"-k", "--no-pager"}
		if !since.IsZero() {
			args = append(args, "--since", since.Format("2006-01-02 15:04:05"))
		}
		out, err := exec.Command(path, args...).Output()
		if err == nil && len(out) > 0 {
			return out, "journalctl", nil
		}
		if err != nil {
			return nil, "journalctl", err
		}
	}
	if path, lerr := exec.LookPath("dmesg"); lerr == nil {
		out, err := exec.Command(path, "--no-pager").Output()
		if err == nil {
			return out, "dmesg", nil
		}
		return nil, "dmesg", err
	}
	return nil, "none", nil
}
