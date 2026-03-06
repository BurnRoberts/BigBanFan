package ipt

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const chainName = "BANNED"

// isIPv6 returns true if the address (with or without CIDR) is an IPv6 address.
func isIPv6(ip string) bool {
	host := ip
	if idx := strings.IndexByte(ip, '/'); idx >= 0 {
		host = ip[:idx]
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.To4() == nil
}

// cmd returns the right iptables binary for the given IP.
func cmd(ip string) string {
	if isIPv6(ip) {
		return "ip6tables"
	}
	return "iptables"
}

// Setup ensures the BANNED chain exists in both iptables (IPv4) and ip6tables (IPv6),
// with the INPUT → BANNED jump active in each. Performs pre-flight checks and a
// post-setup hard verify. Fails fast if iptables is unavailable or permissions are wrong.
// ip6tables is optional — a missing binary logs a warning but does not abort startup.
func Setup() error {
	if err := setupFamily("iptables"); err != nil {
		return err
	}
	// ip6tables is best-effort: warn if missing, don't abort.
	if err := setupFamily("ip6tables"); err != nil {
		fmt.Printf("WARN: ip6tables setup skipped: %v\n", err)
	}
	return nil
}

func setupFamily(bin string) error {
	// Pre-flight: binary in PATH?
	path, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("ipt: %s binary not found in PATH — install iptables package: %w", bin, err)
	}

	// Pre-flight: permission check (fails if not root).
	if err := run(path, "-L", "INPUT", "-n"); err != nil {
		return fmt.Errorf("ipt: cannot read %s INPUT chain — is bigbanfan running as root? %w", bin, err)
	}

	// Create BANNED chain (idempotent).
	if err := run(path, "-N", chainName); err != nil {
		if !chainExistsFamily(bin) {
			return fmt.Errorf("ipt: %s: create chain: %w", bin, err)
		}
	}

	// Insert INPUT → BANNED jump at top of INPUT (idempotent).
	if !jumpExistsFamily(bin) {
		if err := run(path, "-I", "INPUT", "-j", chainName); err != nil {
			return fmt.Errorf("ipt: %s: insert INPUT jump: %w", bin, err)
		}
	}

	// Post-setup hard verify.
	if !chainExistsFamily(bin) {
		return fmt.Errorf("ipt: %s FATAL post-setup — %s chain is NOT present", bin, chainName)
	}
	if !jumpExistsFamily(bin) {
		return fmt.Errorf("ipt: %s FATAL post-setup — INPUT → %s jump is NOT active", bin, chainName)
	}

	return nil
}

// FlushChain flushes all rules from the BANNED chain in both iptables and ip6tables.
// Call at startup before restoring bans from DB to guarantee no stale duplicates.
func FlushChain() error {
	var errs []string
	for _, bin := range []string{"iptables", "ip6tables"} {
		if err := run(bin, "-F", chainName); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", bin, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("ipt: flush chain: %s", strings.Join(errs, "; "))
	}
	return nil
}

// AddBan appends a DROP rule for ip to the correct BANNED chain (iptables or ip6tables).
func AddBan(ip string) error {
	bin := cmd(ip)
	if err := run(bin, "-A", chainName, "-s", cidr(ip), "-j", "DROP"); err != nil {
		return fmt.Errorf("ipt: add ban %s: %w", ip, err)
	}
	return nil
}

// RemoveBan removes the DROP rule for ip from the correct BANNED chain.
func RemoveBan(ip string) error {
	bin := cmd(ip)
	if err := run(bin, "-D", chainName, "-s", cidr(ip), "-j", "DROP"); err != nil {
		return fmt.Errorf("ipt: remove ban %s: %w", ip, err)
	}
	return nil
}

// chainExistsFamily checks whether the BANNED chain is present in the given binary's table.
func chainExistsFamily(bin string) bool {
	return run(bin, "-L", chainName, "-n") == nil
}

// jumpExistsFamily checks whether the INPUT → BANNED jump exists for the given binary.
func jumpExistsFamily(bin string) bool {
	out, err := exec.Command(bin, "-C", "INPUT", "-j", chainName).CombinedOutput()
	_ = out
	return err == nil
}

// cidr converts a bare IP to CIDR notation (/32 for IPv4, /128 for IPv6).
func cidr(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	if isIPv6(ip) {
		return ip + "/128"
	}
	return ip + "/32"
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s: %w", name, args, strings.TrimSpace(string(out)), err)
	}
	return nil
}
