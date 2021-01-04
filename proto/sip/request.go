package sip

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	uuid "github.com/satori/go.uuid"
)

const (
	defaultMaxMemory = 32 << 20 // 32 MB
)

// // ErrMissingFile is returned by FormFile when the provided file field name
// // is either not present in the request or not a file field.
// var ErrMissingFile = errors.New("http: no such file")

// ProtocolError represents an HTTP protocol error.
//
// Deprecated: Not all errors in the http package related to protocol errors
// are of type ProtocolError.
type ProtocolError struct {
	ErrorString string
}

func (pe *ProtocolError) Error() string { return pe.ErrorString }

var (
	// ErrNotSupported is returned by the Push method of Pusher
	// implementations to indicate that HTTP/2 Push support is not
	// available.
	ErrNotSupported = &ProtocolError{"feature not supported"}

	// Deprecated: ErrUnexpectedTrailer is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrUnexpectedTrailer = &ProtocolError{"trailer header without chunked transfer encoding"}

	// ErrMissingBoundary is returned by Request.MultipartReader when the
	// request's Content-Type does not include a "boundary" parameter.
	ErrMissingBoundary = &ProtocolError{"no multipart boundary param in Content-Type"}

	// ErrNotMultipart is returned by Request.MultipartReader when the
	// request's Content-Type is not multipart/form-data.
	ErrNotMultipart = &ProtocolError{"request Content-Type isn't multipart/form-data"}

	// Deprecated: ErrHeaderTooLong is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrHeaderTooLong = &ProtocolError{"header too long"}

	// Deprecated: ErrShortBody is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrShortBody = &ProtocolError{"entity body too short"}

	// Deprecated: ErrMissingContentLength is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrMissingContentLength = &ProtocolError{"missing ContentLength in HEAD response"}
)

func badStringError(what, val string) error { return fmt.Errorf("%s %q", what, val) }

// Headers that Request.Write handles itself and should be skipped.
var reqWriteExcludeHeader = map[string]bool{
	"Via":            true,
	"User-Agent":     true,
	"Content-Length": true,
	"CallID":         true,
	"CSeq":           true,
}

// A Request represents an HTTP request received by a server
// or to be sent by a client.
//
// The field semantics differ slightly between client and server
// usage. In addition to the notes on the fields below, see the
// documentation for Request.Write and RoundTripper.
type Request struct {
	Method                          string
	Address                         Address
	Proto                           string // "HTTP/1.0"
	ProtoMajor                      int    // 1
	ProtoMinor                      int    // 0
	Header                          http.Header
	Body                            io.ReadCloser
	GetBody                         func() (io.ReadCloser, error)
	ContentLength                   int64
	Close                           bool
	LocalAddr                       net.Addr
	RequestURI                      string
	Cancel                          <-chan struct{}
	Response                        *Response
	EnableDefaultContactForRegister bool
}

// ProtoAtLeast reports whether the HTTP protocol used
// in the request is at least major.minor.
func (r *Request) ProtoAtLeast(major, minor int) bool {
	return r.ProtoMajor > major ||
		r.ProtoMajor == major && r.ProtoMinor >= minor
}

// UserAgent returns the client's User-Agent, if sent in the request.
func (r *Request) UserAgent() string {
	return r.Header.Get("User-Agent")
}

// Return value if nonempty, def otherwise.
func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

// NOTE: This is not intended to reflect the actual Go version being used.
// It was changed at the time of Go 1.1 release because the former User-Agent
// had ended up blocked by some intrusion detection systems.
// See https://codereview.appspot.com/7532043.
const defaultUserAgent = "Go-sip-client/1.1"

// Write writes an HTTP/1.1 request, which is the header and body, in wire format.
// This method consults the following fields of the request:
//	Host
//	URL
//	Method (defaults to "GET")
//	Header
//	ContentLength
//	TransferEncoding
//	Body
//
// If Body is present, Content-Length is <= 0 and TransferEncoding
// hasn't been set to "identity", Write adds "Transfer-Encoding:
// chunked" to the header. Body is closed after it is sent.
func (r *Request) Write(w io.Writer) error {
	return r.write(w, false, nil, nil)
}

// WriteProxy is like Write but writes the request in the form
// expected by an HTTP proxy. In particular, WriteProxy writes the
// initial Request-URI line of the request with an absolute URI, per
// section 5.3 of RFC 7230, including the scheme and host.
// In either case, WriteProxy also writes a Host header, using
// either r.Host or r.URL.Host.
func (r *Request) WriteProxy(w io.Writer) error {
	return r.write(w, true, nil, nil)
}

// errMissingHost is returned by Write when there is no Host or URL present in
// the Request.
var errMissingHost = errors.New("http: Request.Write on Request with no Host or URL set")

// extraHeaders may be nil
// waitForContinue may be nil
func (r *Request) write(w io.Writer, usingProxy bool, extraHeaders http.Header, waitForContinue func() bool) (err error) {
	ruri := r.RequestURI
	var bw *bufio.Writer
	if _, ok := w.(io.ByteWriter); !ok {
		bw = bufio.NewWriter(w)
		w = bw
	}

	_, err = fmt.Fprintf(w, "%s %s SIP/2.0\r\n", valueOrDefault(r.Method, "REGISTER"), ruri)
	if err != nil {
		return err
	}
	branch := uuid.Must(uuid.NewV4(), nil).String()
	_, err = fmt.Fprintf(w, "Via: SIP/2.0/UDP %s;rport;branch=%s\r\n", r.LocalAddr.String(), branch)
	if err != nil {
		return err
	}
	callID := uuid.Must(uuid.NewV4(), nil).String()
	_, err = fmt.Fprintf(w, "Call-ID: %s\r\n", callID)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "CSeq: %d %s\r\n", rand.Int()%1000, r.Method)
	if err != nil {
		return err
	}
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	_, err = fmt.Fprintf(w, "User-Agent: %s\r\n", userAgent)
	if err != nil {
		return err
	}

	_, err = fmt.Fprint(w, "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n")
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "From: \"%s\" <sip:%s@%s>;tag=LJ6ACy3pS0aFPBU0ClNf03IcDt0fBf52;\r\n", r.Address.Name, r.Address.AccNumber, r.Address.Host)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "To: \"%s\" <sip:%s@%s>\r\n", r.Address.Name, r.Address.AccNumber, r.Address.Host)
	if err != nil {
		return err
	}

	if r.EnableDefaultContactForRegister {
		_, err = fmt.Fprintf(w, "Contact: \"%s\" <sip:%s@%s;ob>\r\n", r.Address.Name, r.Address.AccNumber, r.LocalAddr.String())
		if err != nil {
			return err
		}
	}

	err = r.Header.WriteSubset(w, reqWriteExcludeHeader)
	if err != nil {
		return err
	}

	// if extraHeaders != nil {
	// 	err = extraHeaders.Write(w)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	_, err = io.WriteString(w, "\r\n")
	if err != nil {
		return err
	}

	// Flush and wait for 100-continue if expected.
	if waitForContinue != nil {
		if bw, ok := w.(*bufio.Writer); ok {
			err = bw.Flush()
			if err != nil {
				return err
			}
		}
		// if trace != nil && trace.Wait100Continue != nil {
		// 	trace.Wait100Continue()
		// }
		if !waitForContinue() {
			r.closeBody()
			return nil
		}
	}

	if bw, ok := w.(*bufio.Writer); ok {
		if err := bw.Flush(); err != nil {
			return err
		}
	}

	if bw != nil {
		return bw.Flush()
	}
	return nil
}

type requestBodyReadError struct{ error }

func ParseSIPVersion(vers string) (major, minor int, ok bool) {
	const Big = 1000000 // arbitrary upper bound
	switch vers {
	case "SIP/1.0":
		return 1, 0, true
	case "SIP/2.0":
		return 2, 0, true
	}
	if !strings.HasPrefix(vers, "SIP/") {
		return 0, 0, false
	}
	dot := strings.Index(vers, ".")
	if dot < 0 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(vers[5:dot])
	if err != nil || major < 0 || major > Big {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(vers[dot+1:])
	if err != nil || minor < 0 || minor > Big {
		return 0, 0, false
	}
	return major, minor, true
}

func validMethod(method string) bool {
	/*
	     Method         = "OPTIONS"                ; Section 9.2
	                    | "GET"                    ; Section 9.3
	                    | "HEAD"                   ; Section 9.4
	                    | "POST"                   ; Section 9.5
	                    | "PUT"                    ; Section 9.6
	                    | "DELETE"                 ; Section 9.7
	                    | "TRACE"                  ; Section 9.8
	                    | "CONNECT"                ; Section 9.9
	                    | extension-method
	   extension-method = token
	     token          = 1*<any CHAR except CTLs or separators>
	*/
	var isNotToken = func(a rune) bool {
		return false
	}
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

// NewRequest wraps NewRequestWithContext using the background context.
func NewRequest(method string, address Address, body io.Reader) (*Request, error) {
	return NewRequestWithContext(context.Background(), method, address, body)
}

func NewRequestWithContext(ctx context.Context, method string, address Address, body io.Reader) (*Request, error) {
	if method == "" {
		method = "REGISTER"
	}
	if !validMethod(method) {
		return nil, fmt.Errorf("net/http: invalid method %q", method)
	}
	rc, ok := body.(io.ReadCloser)
	if !ok && body != nil {
		rc = ioutil.NopCloser(body)
	}
	req := &Request{
		Method:                          method,
		Address:                         address,
		Proto:                           "SIP/2.0",
		ProtoMajor:                      2,
		ProtoMinor:                      0,
		Header:                          make(http.Header),
		Body:                            rc,
		RequestURI:                      fmt.Sprintf("sip:%s", address.String()),
		EnableDefaultContactForRegister: true,
	}
	if body != nil {
		switch v := body.(type) {
		case *bytes.Buffer:
			req.ContentLength = int64(v.Len())
			buf := v.Bytes()
			req.GetBody = func() (io.ReadCloser, error) {
				r := bytes.NewReader(buf)
				return ioutil.NopCloser(r), nil
			}
		case *bytes.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return ioutil.NopCloser(&r), nil
			}
		case *strings.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return ioutil.NopCloser(&r), nil
			}
		default:
			// This is where we'd set it to -1 (at least
			// if body != NoBody) to mean unknown, but
			// that broke people during the Go 1.8 testing
			// period. People depend on it being 0 I
			// guess. Maybe retry later. See Issue 18117.
		}
		if req.GetBody != nil && req.ContentLength == 0 {
			req.Body = http.NoBody
			req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		}
	}

	return req, nil
}

var textprotoReaderPool sync.Pool

// func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
// 	if v := textprotoReaderPool.Get(); v != nil {
// 		tr := v.(*textproto.Reader)
// 		tr.R = br
// 		return tr
// 	}
// 	return textproto.NewReader(br)
// }

// func putTextprotoReader(r *textproto.Reader) {
// 	r.R = nil
// 	textprotoReaderPool.Put(r)
// }

// func copyValues(dst, src url.Values) {
// 	for k, vs := range src {
// 		dst[k] = append(dst[k], vs...)
// 	}
// }

// func (r *Request) wantsClose() bool {
// 	if r.Close {
// 		return true
// 	}
// 	return hasToken(r.Header.get("Connection"), "close")
// }

func (r *Request) closeBody() {
	if r.Body != nil {
		r.Body.Close()
	}
}

// func (r *Request) isReplayable() bool {
// 	return true
// }

// func (r *Request) outgoingLength() int64 {
// 	if r.Body == nil || r.Body == NoBody {
// 		return 0
// 	}
// 	if r.ContentLength != 0 {
// 		return r.ContentLength
// 	}
// 	return -1
// }

// func requestMethodUsuallyLacksBody(method string) bool {
// 	switch method {
// 	case "REGISTER":
// 		return true
// 	}
// 	return false
// }
