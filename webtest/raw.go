package webtest

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Raw sends an entire request verbatim over plain TCP before reading the
// response. It cannot use a TLS test server and rejects HEAD requests;
// use Client.Do to inspect a HEAD response.
// Include "Connection: close" so an EOF-delimited response can end.
// Raw splits the header lines but does not apply MIME or URL validation.
// The connection has a 30-second deadline including dial time.
func Raw(t testing.TB, addr string, req io.Reader) *RawResponse {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("raw request: dial %s: %v", addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatalf("raw request: set deadline: %v", err)
	}
	// A HEAD response may advertise a length without sending that body.
	// Peek only at the method prefix and send the buffered bytes unchanged.
	out := bufio.NewReaderSize(req, len("HEAD "))
	if prefix, _ := out.Peek(len("HEAD ")); string(prefix) == "HEAD " {
		t.Fatal("Raw does not support HEAD; use Client.Do instead")
	}
	if _, err := io.Copy(conn, out); err != nil {
		t.Fatalf("raw request: write: %v", err)
	}

	reader := bufio.NewReader(conn)
	res := readRawHead(t, reader)
	for res.Status >= 100 && res.Status < 200 && res.Status != http.StatusSwitchingProtocols {
		res = readRawHead(t, reader)
	}
	res.Body = readRawBody(t, reader, res)
	return res
}

// RawResponse is an HTTP/1 response with the status and body framing decoded
// but the header lines left unvalidated.
type RawResponse struct {
	StatusLine string
	Status     int
	// Headers holds name and value in wire order. The value includes any
	// whitespace after the colon. A line without a colon is kept in the
	// name slot with an empty value.
	Headers [][2]string
	// Body is the payload, with chunk framing removed if present.
	Body []byte
}

// Values returns values in wire order for a case-insensitive name. It removes
// leading spaces and tabs after the colon but otherwise leaves bytes alone.
func (r *RawResponse) Values(name string) []string {
	var values []string
	for _, pair := range r.Headers {
		if strings.EqualFold(name, pair[0]) {
			values = append(values, strings.TrimLeft(pair[1], " \t"))
		}
	}
	return values
}

func readRawHead(t testing.TB, reader *bufio.Reader) *RawResponse {
	t.Helper()
	res := &RawResponse{StatusLine: readRawLine(t, reader)}
	fields := strings.Fields(res.StatusLine)
	if len(fields) < 2 {
		t.Fatalf("raw response: missing status in %q", res.StatusLine)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("raw response: invalid status in %q", res.StatusLine)
	}
	res.Status = code
	for {
		line := readRawLine(t, reader)
		if line == "" {
			return res
		}
		name, value, _ := strings.Cut(line, ":")
		res.Headers = append(res.Headers, [2]string{name, value})
	}
}

func readRawLine(t testing.TB, reader *bufio.Reader) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("raw response: read header line: %v", err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
}

func readRawBody(t testing.TB, reader *bufio.Reader, res *RawResponse) []byte {
	t.Helper()
	switch res.Status {
	case http.StatusSwitchingProtocols, http.StatusNoContent, http.StatusNotModified:
		return nil
	}
	var body io.Reader = reader
	var length int64 = -1
	if encodings := res.Values("Transfer-Encoding"); len(encodings) > 0 {
		last := encodings[len(encodings)-1]
		if i := strings.LastIndexByte(last, ','); i >= 0 {
			last = last[i+1:]
		}
		if strings.EqualFold(strings.TrimSpace(last), "chunked") {
			body = httputil.NewChunkedReader(reader)
		}
	} else if lengths := res.Values("Content-Length"); len(lengths) > 0 {
		n, err := strconv.ParseInt(strings.TrimSpace(lengths[0]), 10, 64)
		if err != nil || n < 0 {
			t.Fatalf("raw response: invalid Content-Length %q", lengths[0])
		}
		length = n
		body = io.LimitReader(reader, length)
	}
	p, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("raw response: read body: %v", err)
	}
	if length >= 0 && int64(len(p)) != length {
		t.Fatalf("raw response: got %d body bytes, Content-Length promised %d", len(p), length)
	}
	return p
}
