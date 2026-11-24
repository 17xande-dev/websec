package csrf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type origin struct {
	scheme string
	host   string
}

// ValidateOrigin reports whether origin is acceptable as Config.Origin or a
// Config.TrustedOrigins entry with the given Insecure setting: a lowercase
// scheme://host[:port] with no path, query, fragment, userinfo or trailing
// slash; https, or http only when insecure; no default port (:443 for https,
// :80 for http); an ASCII host with IP literals in canonical form; and a port,
// if present, written as browsers send it (1-65535, no leading zero).
// New applies exactly these rules.
func ValidateOrigin(origin string, insecure bool) error {
	if _, err := parseOrigin(origin, insecure); err != nil {
		return fmt.Errorf("csrf: %w", err)
	}
	return nil
}

func originPolicy(own string, trusted []string, insecure bool) (func(*url.URL) bool, error) {
	public, err := parseOrigin(own, insecure)
	if err != nil {
		return nil, fmt.Errorf("csrf: Origin: %w", err)
	}
	allowed := map[origin]bool{public: true}
	for i, raw := range trusted {
		o, err := parseOrigin(raw, insecure)
		if err != nil {
			return nil, fmt.Errorf("csrf: TrustedOrigins[%d]: %w", i, err)
		}
		// An allow-list shared with a CORS setup legitimately repeats the
		// public origin or an earlier entry; a harmless duplicate must not
		// fail startup.
		allowed[o] = true
	}
	return func(u *url.URL) bool {
		return allowed[origin{u.Scheme, u.Host}]
	}, nil
}

var errOriginFormat = errors.New("want a lowercase scheme://host[:port] with no other URL parts")

func parseOrigin(raw string, insecure bool) (origin, error) {
	u, err := url.Parse(raw)
	// Reconstructing catches even empty queries/fragments, and rejects
	// uppercase schemes (url.Parse would otherwise silently normalize them).
	if err != nil || u.Hostname() == "" || raw != u.Scheme+"://"+u.Host {
		return origin{}, errOriginFormat
	}
	if err := validateOriginAuthority(u); err != nil {
		return origin{}, err
	}
	if raw != strings.ToLower(raw) {
		return origin{}, errOriginFormat
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !insecure {
			return origin{}, errors.New("http origin requires Insecure")
		}
	default:
		return origin{}, errors.New("scheme must be https or http")
	}
	if port := u.Port(); port != "" {
		// The authority check bounds the port. Match the browser's spelling
		// too, so a configured port cannot silently fail to match.
		if port == "0" || (len(port) > 1 && port[0] == '0') {
			return origin{}, fmt.Errorf("port %s is not how browsers write it; use 1-65535 without leading zeros", port)
		}
		if port == defaultPorts[u.Scheme] {
			return origin{}, fmt.Errorf("port %s is the default for %s and browsers omit it; remove it", port, u.Scheme)
		}
	}
	return origin{u.Scheme, u.Host}, nil
}

var defaultPorts = map[string]string{"https": "443", "http": "80"}

func validateOriginAuthority(u *url.URL) error {
	host := u.Hostname()
	for i := range len(host) {
		if host[i] >= 0x80 {
			return errors.New("origin host must be ASCII; use Punycode for internationalized names")
		}
	}
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return errOriginFormat
		}
		canonical := ip.String()
		if ip.Is4In6() {
			// netip writes mapped addresses with a dotted suffix; browsers
			// write the last two pieces in hex, like any other IPv6 literal.
			v4 := ip.As4()
			canonical = fmt.Sprintf("::ffff:%x:%x", binary.BigEndian.Uint16(v4[:2]), binary.BigEndian.Uint16(v4[2:]))
		}
		if host != canonical {
			return fmt.Errorf("IPv6 origin host must use canonical spelling; use [%s]", canonical)
		}
	} else if strings.ContainsAny(host, ":[]") {
		return errOriginFormat
	} else if ipv4Spelling(host) {
		if ip, err := netip.ParseAddr(host); err != nil || !ip.Is4() {
			return errors.New("IPv4 origin host must use canonical dotted-quad spelling")
		}
	}
	if port := u.Port(); port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return errOriginFormat
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return errOriginFormat
	}
	return nil
}

// ipv4Spelling recognizes IPv4-shaped hosts, including legacy browser
// spellings. Check the shape without interpreting values; netip accepts only
// canonical dotted quads. Names with DNS labels are left alone.
func ipv4Spelling(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if strings.Count(host, ".") > 3 {
		return false
	}
	for part := range strings.SplitSeq(host, ".") {
		if part == "" {
			return false
		}
		if hex, ok := strings.CutPrefix(part, "0x"); ok {
			if strings.ContainsFunc(hex, func(r rune) bool {
				return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f')
			}) {
				return false
			}
		} else if strings.ContainsFunc(part, func(r rune) bool { return r < '0' || r > '9' }) {
			return false
		}
	}
	return true
}
