package netns

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

// SubIDRange represents a subordinate UID/GID range from /etc/subuid or /etc/subgid.
type SubIDRange struct {
	Start int
	Count int
}

// ParseSubIDs reads /etc/subuid and /etc/subgid for the current user and
// returns the first matching range from each. Returns nil for either if no
// entry is found (Podman won't work but seki still functions).
func ParseSubIDs() (uid, gid *SubIDRange) {
	u, err := user.Current()
	if err != nil {
		return nil, nil
	}
	uid = parseSubIDFile("/etc/subuid", u.Username, u.Uid)
	gid = parseSubIDFile("/etc/subgid", u.Username, u.Uid)
	return uid, gid
}

// parseSubIDFile parses a file in the format "name:start:count" and returns
// the first range matching the given username or numeric uid.
func parseSubIDFile(path, username, uid string) *SubIDRange {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] != username && parts[0] != uid {
			continue
		}
		start, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		count, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		return &SubIDRange{Start: start, Count: count}
	}
	return nil
}

const subIDEnvKey = "SEKI_SUBIDS"

// subIDEnvValue encodes a SubIDRange pair as an environment variable value.
func subIDEnvValue(uid, gid *SubIDRange) string {
	if uid == nil || gid == nil {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d", uid.Start, uid.Count, gid.Start, gid.Count)
}

// applySubIDMappings calls newuidmap/newgidmap to extend the uid/gid mappings
// of a child process. The child must already have a single-entry mapping
// (written by Go's SysProcAttr), and this adds the subuid/subgid range on top.
//
// Note: newuidmap replaces the entire uid_map, so we must include the original
// single-entry mapping in the arguments.
func applySubIDMappings(pid int, subUID, subGID *SubIDRange) error {
	pidStr := strconv.Itoa(pid)
	uidStr := strconv.Itoa(os.Getuid())
	gidStr := strconv.Itoa(os.Getgid())

	// newuidmap <pid> <inner> <outer> <count> [<inner> <outer> <count>] ...
	uidCmd := exec.Command("newuidmap", pidStr,
		"0", uidStr, "1",
		strconv.Itoa(subUID.Start), strconv.Itoa(subUID.Start), strconv.Itoa(subUID.Count),
	)
	if out, err := uidCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("newuidmap: %w: %s", err, out)
	}

	gidCmd := exec.Command("newgidmap", pidStr,
		"0", gidStr, "1",
		strconv.Itoa(subGID.Start), strconv.Itoa(subGID.Start), strconv.Itoa(subGID.Count),
	)
	if out, err := gidCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("newgidmap: %w: %s", err, out)
	}

	return nil
}

// ParseSubIDEnv decodes the SEKI_SUBIDS environment variable set by the parent.
func ParseSubIDEnv() (uid, gid *SubIDRange) {
	v := os.Getenv(subIDEnvKey)
	if v == "" {
		return nil, nil
	}
	parts := strings.SplitN(v, ":", 4)
	if len(parts) != 4 {
		return nil, nil
	}
	uStart, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, nil
	}
	uCount, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, nil
	}
	gStart, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, nil
	}
	gCount, err := strconv.Atoi(parts[3])
	if err != nil {
		return nil, nil
	}
	return &SubIDRange{Start: uStart, Count: uCount}, &SubIDRange{Start: gStart, Count: gCount}
}
