package main

import (
	"fmt"
	"strconv"
	"strings"
)

// attrNames maps well-known RADIUS attribute type numbers (RFC 2865, 2866,
// 2869, 3579) to their display names, used for human-readable logging and
// for resolving attribute names in fuzz.txt wordlists.
//
// This is v2's own independent copy of the same concept used by client/v1's
// dictionary.go — kept separate on purpose so v2 has no dependency on v1.
var attrNames = map[byte]string{
	1:  "User-Name",
	2:  "User-Password",
	3:  "CHAP-Password",
	4:  "NAS-IP-Address",
	5:  "NAS-Port",
	6:  "Service-Type",
	7:  "Framed-Protocol",
	8:  "Framed-IP-Address",
	9:  "Framed-IP-Netmask",
	10: "Framed-Routing",
	11: "Filter-Id",
	12: "Framed-MTU",
	13: "Framed-Compression",
	14: "Login-IP-Host",
	15: "Login-Service",
	16: "Login-TCP-Port",
	18: "Reply-Message",
	19: "Callback-Number",
	20: "Callback-Id",
	22: "Framed-Route",
	23: "Framed-IPX-Network",
	24: "State",
	25: "Class",
	26: "Vendor-Specific",
	27: "Session-Timeout",
	28: "Idle-Timeout",
	29: "Termination-Action",
	30: "Called-Station-Id",
	31: "Calling-Station-Id",
	32: "NAS-Identifier",
	33: "Proxy-State",
	34: "Login-LAT-Service",
	35: "Login-LAT-Node",
	36: "Login-LAT-Group",
	37: "Framed-AppleTalk-Link",
	38: "Framed-AppleTalk-Network",
	39: "Framed-AppleTalk-Zone",
	40: "Acct-Status-Type",
	41: "Acct-Delay-Time",
	42: "Acct-Input-Octets",
	43: "Acct-Output-Octets",
	44: "Acct-Session-Id",
	45: "Acct-Authentic",
	46: "Acct-Session-Time",
	47: "Acct-Input-Packets",
	48: "Acct-Output-Packets",
	49: "Acct-Terminate-Cause",
	60: "CHAP-Challenge",
	61: "NAS-Port-Type",
	62: "Port-Limit",
	63: "Login-LAT-Port",
	79: "EAP-Message",
	80: "Message-Authenticator",
	87: "NAS-Port-Id",
}

// attrNameToType is the reverse lookup (lowercased), used to parse fuzz.txt
// attribute tokens given by name instead of numeric type.
var attrNameToType = func() map[string]byte {
	m := make(map[string]byte, len(attrNames))
	for t, name := range attrNames {
		m[strings.ToLower(name)] = t
	}
	return m
}()

// attrName returns the display name for t, or "Unknown" if unmapped.
func attrName(t byte) string {
	if n, ok := attrNames[t]; ok {
		return n
	}
	return "Unknown"
}

// resolveAttrType parses a fuzz.txt "attr" token into a RADIUS attribute
// type number: a plain integer (0-255) is used directly, otherwise the
// token is looked up case-insensitively in attrNameToType.
func resolveAttrType(token string) (byte, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0, fmt.Errorf("empty attribute token")
	}
	if n, err := strconv.Atoi(token); err == nil {
		if n < 0 || n > 255 {
			return 0, fmt.Errorf("attribute type %d out of range (0-255)", n)
		}
		return byte(n), nil
	}
	if t, ok := attrNameToType[strings.ToLower(token)]; ok {
		return t, nil
	}
	return 0, fmt.Errorf("unknown attribute name %q", token)
}
