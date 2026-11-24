package csrf

import (
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

func parseOrigin(raw string, insecure bool) (origin, error) {
	u, err := url.Parse(raw)
	// Reconstructing catches even empty queries/fragments, and rejects
	// uppercase schemes (url.Parse would otherwise silently normalize them).
	if err != nil || u.Hostname() == "" || raw != u.Scheme+"://"+u.Host ||
		raw != strings.ToLower(raw) || !validAuthority(u) {
		return origin{}, errors.New("want a lowercase scheme://host[:port] with no other URL parts")
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
	// Browsers leave the default port out of the Origin header, so an entry
	// that spells it could never match: a silently dead entry.
	if port := u.Port(); port != "" && port == defaultPorts[u.Scheme] {
		return origin{}, fmt.Errorf("port %s is the default for %s and browsers omit it; remove it", port, u.Scheme)
	}
	return origin{u.Scheme, u.Host}, nil
}

var defaultPorts = map[string]string{"https": "443", "http": "80"}

func validAuthority(u *url.URL) bool {
	host := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return false
		}
	} else if strings.ContainsAny(host, ":[]") {
		return false
	}
	if port := u.Port(); port != "" {
		_, err := strconv.ParseUint(port, 10, 16)
		return err == nil
	}
	return !strings.HasSuffix(u.Host, ":")
}
