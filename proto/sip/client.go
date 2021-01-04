// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP client. See RFC 7230 through 7235.
//
// This is the high-level Client interface.
// The low-level implementation is in transport.go.

package sip

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
)

// A Client is an HTTP client. Its zero value (DefaultClient) is a
// usable client that uses DefaultTransport.
//
// The Client's Transport typically has internal state (cached TCP
// connections), so Clients should be reused instead of created as
// needed. Clients are safe for concurrent use by multiple goroutines.
//
// A Client is higher-level than a RoundTripper (such as Transport)
// and additionally handles HTTP details such as cookies and
// redirects.
//
// When following redirects, the Client will forward all headers set on the
// initial Request except:
//
// • when forwarding sensitive headers like "Authorization",
// "WWW-Authenticate", and "Cookie" to untrusted targets.
// These headers will be ignored when following a redirect to a domain
// that is not a subdomain match or exact match of the initial domain.
// For example, a redirect from "foo.com" to either "foo.com" or "sub.foo.com"
// will forward the sensitive headers, but a redirect to "bar.com" will not.
//
// • when forwarding the "Cookie" header with a non-nil cookie Jar.
// Since each redirect may mutate the state of the cookie jar,
// a redirect may possibly alter a cookie set in the initial request.
// When forwarding the "Cookie" header, any mutated cookies will be omitted,
// with the expectation that the Jar will insert those mutated cookies
// with the updated values (assuming the origin matches).
// If Jar is nil, the initial cookies are forwarded without change.
//
type Client struct {
	Dailer net.Dialer
}

// DefaultClient is the default Client and is used by Get, Head, and Post.
var DefaultClient = &Client{Dailer: net.Dialer{}}

// RoundTripper is an interface representing the ability to execute a
// single HTTP transaction, obtaining the Response for a given Request.
//

// // refererForURL returns a referer without any authentication info or
// // an empty string if lastReq scheme is https and newReq scheme is http.
// func refererForURL(lastReq, newReq *url.URL) string {
// 	// https://tools.ietf.org/html/rfc7231#section-5.5.2
// 	//   "Clients SHOULD NOT include a Referer header field in a
// 	//    (non-secure) HTTP request if the referring page was
// 	//    transferred with a secure protocol."
// 	if lastReq.Scheme == "https" && newReq.Scheme == "http" {
// 		return ""
// 	}
// 	referer := lastReq.String()
// 	if lastReq.User != nil {
// 		// This is not very efficient, but is the best we can
// 		// do without:
// 		// - introducing a new method on URL
// 		// - creating a race condition
// 		// - copying the URL struct manually, which would cause
// 		//   maintenance problems down the line
// 		auth := lastReq.User.String() + "@"
// 		referer = strings.Replace(referer, auth, "", 1)
// 	}
// 	return referer
// }

// didTimeout is non-nil only if err != nil.
// func (c *Client) send(req *Request, deadline time.Time) (resp *Response, didTimeout func() bool, err error) {
// 	if c.Jar != nil {
// 		for _, cookie := range c.Jar.Cookies(req.URL) {
// 			req.AddCookie(cookie)
// 		}
// 	}
// 	resp, didTimeout, err = send(req, c.transport(), deadline)
// 	if err != nil {
// 		return nil, didTimeout, err
// 	}
// 	if c.Jar != nil {
// 		if rc := resp.Cookies(); len(rc) > 0 {
// 			c.Jar.SetCookies(req.URL, rc)
// 		}
// 	}
// 	return resp, nil, nil
// }

// func (c *Client) deadline() time.Time {
// 	if c.Timeout > 0 {
// 		return time.Now().Add(c.Timeout)
// 	}
// 	return time.Time{}
// }

// func (c *Client) transport() RoundTripper {
// 	if c.Transport != nil {
// 		return c.Transport
// 	}
// 	return DefaultTransport
// }

// // send issues an HTTP request.
// // Caller should close resp.Body when done reading from it.
// func send(ireq *Request, rt RoundTripper, deadline time.Time) (resp *Response, didTimeout func() bool, err error) {
// 	req := ireq // req is either the original request, or a modified fork

// 	if rt == nil {
// 		req.closeBody()
// 		return nil, alwaysFalse, errors.New("http: no Client.Transport or DefaultTransport")
// 	}

// 	if req.URL == nil {
// 		req.closeBody()
// 		return nil, alwaysFalse, errors.New("http: nil Request.URL")
// 	}

// 	if req.RequestURI != "" {
// 		req.closeBody()
// 		return nil, alwaysFalse, errors.New("http: Request.RequestURI can't be set in client requests")
// 	}

// 	// forkReq forks req into a shallow clone of ireq the first
// 	// time it's called.
// 	forkReq := func() {
// 		if ireq == req {
// 			req = new(Request)
// 			*req = *ireq // shallow clone
// 		}
// 	}

// 	// Most the callers of send (Get, Post, et al) don't need
// 	// Headers, leaving it uninitialized. We guarantee to the
// 	// Transport that this has been initialized, though.
// 	if req.Header == nil {
// 		forkReq()
// 		req.Header = make(Header)
// 	}

// 	if u := req.URL.User; u != nil && req.Header.Get("Authorization") == "" {
// 		username := u.Username()
// 		password, _ := u.Password()
// 		forkReq()
// 		req.Header = cloneOrMakeHeader(ireq.Header)
// 		req.Header.Set("Authorization", "Basic "+basicAuth(username, password))
// 	}

// 	if !deadline.IsZero() {
// 		forkReq()
// 	}
// 	stopTimer, didTimeout := setRequestCancel(req, rt, deadline)

// 	resp, err = rt.RoundTrip(req)
// 	if err != nil {
// 		stopTimer()
// 		if resp != nil {
// 			log.Printf("RoundTripper returned a response & error; ignoring response")
// 		}
// 		if tlsErr, ok := err.(tls.RecordHeaderError); ok {
// 			// If we get a bad TLS record header, check to see if the
// 			// response looks like HTTP and give a more helpful error.
// 			// See golang.org/issue/11111.
// 			if string(tlsErr.RecordHeader[:]) == "HTTP/" {
// 				err = errors.New("http: server gave HTTP response to HTTPS client")
// 			}
// 		}
// 		return nil, didTimeout, err
// 	}
// 	if resp == nil {
// 		return nil, didTimeout, fmt.Errorf("http: RoundTripper implementation (%T) returned a nil *Response with a nil error", rt)
// 	}
// 	if resp.Body == nil {
// 		// The documentation on the Body field says “The http Client and Transport
// 		// guarantee that Body is always non-nil, even on responses without a body
// 		// or responses with a zero-length body.” Unfortunately, we didn't document
// 		// that same constraint for arbitrary RoundTripper implementations, and
// 		// RoundTripper implementations in the wild (mostly in tests) assume that
// 		// they can use a nil Body to mean an empty one (similar to Request.Body).
// 		// (See https://golang.org/issue/38095.)
// 		//
// 		// If the ContentLength allows the Body to be empty, fill in an empty one
// 		// here to ensure that it is non-nil.
// 		if resp.ContentLength > 0 && req.Method != "HEAD" {
// 			return nil, didTimeout, fmt.Errorf("http: RoundTripper implementation (%T) returned a *Response with content length %d but a nil Body", rt, resp.ContentLength)
// 		}
// 		resp.Body = ioutil.NopCloser(strings.NewReader(""))
// 	}
// 	if !deadline.IsZero() {
// 		resp.Body = &cancelTimerBody{
// 			stop:          stopTimer,
// 			rc:            resp.Body,
// 			reqDidTimeout: didTimeout,
// 		}
// 	}
// 	return resp, nil, nil
// }

// // timeBeforeContextDeadline reports whether the non-zero Time t is
// // before ctx's deadline, if any. If ctx does not have a deadline, it
// // always reports true (the deadline is considered infinite).
// func timeBeforeContextDeadline(t time.Time, ctx context.Context) bool {
// 	d, ok := ctx.Deadline()
// 	if !ok {
// 		return true
// 	}
// 	return t.Before(d)
// }

// // knownRoundTripperImpl reports whether rt is a RoundTripper that's
// // maintained by the Go team and known to implement the latest
// // optional semantics (notably contexts). The Request is used
// // to check whether this particular request is using an alternate protocol,
// // in which case we need to check the RoundTripper for that protocol.
// func knownRoundTripperImpl(rt RoundTripper, req *Request) bool {
// 	switch t := rt.(type) {
// 	case *Transport:
// 		if altRT := t.alternateRoundTripper(req); altRT != nil {
// 			return knownRoundTripperImpl(altRT, req)
// 		}
// 		return true
// 	case *http2Transport, http2noDialH2RoundTripper:
// 		return true
// 	}
// 	// There's a very minor chance of a false positive with this.
// 	// Insted of detecting our golang.org/x/net/http2.Transport,
// 	// it might detect a Transport type in a different http2
// 	// package. But I know of none, and the only problem would be
// 	// some temporarily leaked goroutines if the transport didn't
// 	// support contexts. So this is a good enough heuristic:
// 	if reflect.TypeOf(rt).String() == "*http2.Transport" {
// 		return true
// 	}
// 	return false
// }

// // setRequestCancel sets req.Cancel and adds a deadline context to req
// // if deadline is non-zero. The RoundTripper's type is used to
// // determine whether the legacy CancelRequest behavior should be used.
// //
// // As background, there are three ways to cancel a request:
// // First was Transport.CancelRequest. (deprecated)
// // Second was Request.Cancel.
// // Third was Request.Context.
// // This function populates the second and third, and uses the first if it really needs to.
// func setRequestCancel(req *Request, rt RoundTripper, deadline time.Time) (stopTimer func(), didTimeout func() bool) {
// 	if deadline.IsZero() {
// 		return nop, alwaysFalse
// 	}
// 	knownTransport := knownRoundTripperImpl(rt, req)
// 	oldCtx := req.Context()

// 	if req.Cancel == nil && knownTransport {
// 		// If they already had a Request.Context that's
// 		// expiring sooner, do nothing:
// 		if !timeBeforeContextDeadline(deadline, oldCtx) {
// 			return nop, alwaysFalse
// 		}

// 		var cancelCtx func()
// 		req.ctx, cancelCtx = context.WithDeadline(oldCtx, deadline)
// 		return cancelCtx, func() bool { return time.Now().After(deadline) }
// 	}
// 	initialReqCancel := req.Cancel // the user's original Request.Cancel, if any

// 	var cancelCtx func()
// 	if oldCtx := req.Context(); timeBeforeContextDeadline(deadline, oldCtx) {
// 		req.ctx, cancelCtx = context.WithDeadline(oldCtx, deadline)
// 	}

// 	cancel := make(chan struct{})
// 	req.Cancel = cancel

// 	doCancel := func() {
// 		// The second way in the func comment above:
// 		close(cancel)
// 		// The first way, used only for RoundTripper
// 		// implementations written before Go 1.5 or Go 1.6.
// 		type canceler interface{ CancelRequest(*Request) }
// 		if v, ok := rt.(canceler); ok {
// 			v.CancelRequest(req)
// 		}
// 	}

// 	stopTimerCh := make(chan struct{})
// 	var once sync.Once
// 	stopTimer = func() {
// 		once.Do(func() {
// 			close(stopTimerCh)
// 			if cancelCtx != nil {
// 				cancelCtx()
// 			}
// 		})
// 	}

// 	timer := time.NewTimer(time.Until(deadline))
// 	var timedOut atomicBool

// 	go func() {
// 		select {
// 		case <-initialReqCancel:
// 			doCancel()
// 			timer.Stop()
// 		case <-timer.C:
// 			timedOut.setTrue()
// 			doCancel()
// 		case <-stopTimerCh:
// 			timer.Stop()
// 		}
// 	}()

// 	return stopTimer, timedOut.isSet
// }

// // See 2 (end of page 4) https://www.ietf.org/rfc/rfc2617.txt
// // "To receive authorization, the client sends the userid and password,
// // separated by a single colon (":") character, within a base64
// // encoded string in the credentials."
// // It is not meant to be urlencoded.
// func basicAuth(username, password string) string {
// 	auth := username + ":" + password
// 	return base64.StdEncoding.EncodeToString([]byte(auth))
// }

// // Get issues a GET to the specified URL. If the response is one of
// // the following redirect codes, Get follows the redirect, up to a
// // maximum of 10 redirects:
// //
// //    301 (Moved Permanently)
// //    302 (Found)
// //    303 (See Other)
// //    307 (Temporary Redirect)
// //    308 (Permanent Redirect)
// //
// // An error is returned if there were too many redirects or if there
// // was an HTTP protocol error. A non-2xx response doesn't cause an
// // error. Any returned error will be of type *url.Error. The url.Error
// // value's Timeout method will report true if request timed out or was
// // canceled.
// //
// // When err is nil, resp always contains a non-nil resp.Body.
// // Caller should close resp.Body when done reading from it.
// //
// // Get is a wrapper around DefaultClient.Get.
// //
// // To make a request with custom headers, use NewRequest and
// // DefaultClient.Do.
// func Get(url string) (resp *Response, err error) {
// 	return DefaultClient.Get(url)
// }
func RegisterAddBinding(addr Address, extraHeaders http.Header) (resp *Response, err error) {
	return DefaultClient.RegisterAddBinding(addr, extraHeaders)
}

// // Get issues a GET to the specified URL. If the response is one of the
// // following redirect codes, Get follows the redirect after calling the
// // Client's CheckRedirect function:
// //
// //    301 (Moved Permanently)
// //    302 (Found)
// //    303 (See Other)
// //    307 (Temporary Redirect)
// //    308 (Permanent Redirect)
// //
// // An error is returned if the Client's CheckRedirect function fails
// // or if there was an HTTP protocol error. A non-2xx response doesn't
// // cause an error. Any returned error will be of type *url.Error. The
// // url.Error value's Timeout method will report true if the request
// // timed out.
// //
// // When err is nil, resp always contains a non-nil resp.Body.
// // Caller should close resp.Body when done reading from it.
// //
// // To make a request with custom headers, use NewRequest and Client.Do.
func (c *Client) RegisterAddBinding(addr Address, extraHeaders http.Header) (*Response, error) {
	req, err := NewRequest("REGISTER", addr, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range extraHeaders {
		req.Header.Add(k, v[0])
	}
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	hash := WwwDigest(req.Address.AccNumber, GetRealm(resp.Header.Get("Www-Authenticate")), req.Address.Password, req.Method, req.RequestURI, GetNonce(resp.Header.Get("Www-Authenticate")))
	req.Header.Add("Authorization", fmt.Sprintf("%s,response=\"%s\",username=\"%s\",uri=\"sip:%s\"", resp.Header.Get("WWW-Authenticate"), hash, req.Address.AccNumber, req.Address.String()))
	return c.Do(req)
}

// func alwaysFalse() bool { return false }

// // ErrUseLastResponse can be returned by Client.CheckRedirect hooks to
// // control how redirects are processed. If returned, the next request
// // is not sent and the most recent response is returned with its body
// // unclosed.
// var ErrUseLastResponse = errors.New("net/http: use last response")

// // checkRedirect calls either the user's configured CheckRedirect
// // function, or the default.
// func (c *Client) checkRedirect(req *Request, via []*Request) error {
// 	fn := c.CheckRedirect
// 	if fn == nil {
// 		fn = defaultCheckRedirect
// 	}
// 	return fn(req, via)
// }

// // redirectBehavior describes what should happen when the
// // client encounters a 3xx status code from the server
// func redirectBehavior(reqMethod string, resp *Response, ireq *Request) (redirectMethod string, shouldRedirect, includeBody bool) {
// 	switch resp.StatusCode {
// 	case 301, 302, 303:
// 		redirectMethod = reqMethod
// 		shouldRedirect = true
// 		includeBody = false

// 		// RFC 2616 allowed automatic redirection only with GET and
// 		// HEAD requests. RFC 7231 lifts this restriction, but we still
// 		// restrict other methods to GET to maintain compatibility.
// 		// See Issue 18570.
// 		if reqMethod != "GET" && reqMethod != "HEAD" {
// 			redirectMethod = "GET"
// 		}
// 	case 307, 308:
// 		redirectMethod = reqMethod
// 		shouldRedirect = true
// 		includeBody = true

// 		// Treat 307 and 308 specially, since they're new in
// 		// Go 1.8, and they also require re-sending the request body.
// 		if resp.Header.Get("Location") == "" {
// 			// 308s have been observed in the wild being served
// 			// without Location headers. Since Go 1.7 and earlier
// 			// didn't follow these codes, just stop here instead
// 			// of returning an error.
// 			// See Issue 17773.
// 			shouldRedirect = false
// 			break
// 		}
// 		if ireq.GetBody == nil && ireq.outgoingLength() != 0 {
// 			// We had a request body, and 307/308 require
// 			// re-sending it, but GetBody is not defined. So just
// 			// return this response to the user instead of an
// 			// error, like we did in Go 1.7 and earlier.
// 			shouldRedirect = false
// 		}
// 	}
// 	return redirectMethod, shouldRedirect, includeBody
// }

// // urlErrorOp returns the (*url.Error).Op value to use for the
// // provided (*Request).Method value.
// func urlErrorOp(method string) string {
// 	if method == "" {
// 		return "Get"
// 	}
// 	return method[:1] + strings.ToLower(method[1:])
// }

// // Do sends an HTTP request and returns an HTTP response, following
// // policy (such as redirects, cookies, auth) as configured on the
// // client.
// //
// // An error is returned if caused by client policy (such as
// // CheckRedirect), or failure to speak HTTP (such as a network
// // connectivity problem). A non-2xx status code doesn't cause an
// // error.
// //
// // If the returned error is nil, the Response will contain a non-nil
// // Body which the user is expected to close. If the Body is not both
// // read to EOF and closed, the Client's underlying RoundTripper
// // (typically Transport) may not be able to re-use a persistent TCP
// // connection to the server for a subsequent "keep-alive" request.
// //
// // The request Body, if non-nil, will be closed by the underlying
// // Transport, even on errors.
// //
// // On error, any Response can be ignored. A non-nil Response with a
// // non-nil error only occurs when CheckRedirect fails, and even then
// // the returned Response.Body is already closed.
// //
// // Generally Get, Post, or PostForm will be used instead of Do.
// //
// // If the server replies with a redirect, the Client first uses the
// // CheckRedirect function to determine whether the redirect should be
// // followed. If permitted, a 301, 302, or 303 redirect causes
// // subsequent requests to use HTTP method GET
// // (or HEAD if the original request was HEAD), with no body.
// // A 307 or 308 redirect preserves the original HTTP method and body,
// // provided that the Request.GetBody function is defined.
// // The NewRequest function automatically sets GetBody for common
// // standard library body types.
// //
// // Any returned error will be of type *url.Error. The url.Error
// // value's Timeout method will report true if request timed out or was
// // canceled.
func (c *Client) Do(req *Request) (*Response, error) {
	return c.do(req)
}

// var testHookClientDoResult func(retres *Response, reterr error)

func (c *Client) do(req *Request) (retres *Response, reterr error) {
	conn, err := c.Dailer.Dial(req.Address.Network(), req.Address.String())
	if err != nil {
		log.Fatal(err)
	}
	req.LocalAddr = conn.LocalAddr()
	err = req.Write(conn)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := ReadResponse(bufio.NewReader(conn), req)
	return resp, err
}

// // makeHeadersCopier makes a function that copies headers from the
// // initial Request, ireq. For every redirect, this function must be called
// // so that it can copy headers into the upcoming Request.
// func (c *Client) makeHeadersCopier(ireq *Request) func(*Request) {
// 	// The headers to copy are from the very initial request.
// 	// We use a closured callback to keep a reference to these original headers.
// 	var (
// 		ireqhdr  = cloneOrMakeHeader(ireq.Header)
// 		icookies map[string][]*Cookie
// 	)
// 	if c.Jar != nil && ireq.Header.Get("Cookie") != "" {
// 		icookies = make(map[string][]*Cookie)
// 		for _, c := range ireq.Cookies() {
// 			icookies[c.Name] = append(icookies[c.Name], c)
// 		}
// 	}

// 	preq := ireq // The previous request
// 	return func(req *Request) {
// 		// If Jar is present and there was some initial cookies provided
// 		// via the request header, then we may need to alter the initial
// 		// cookies as we follow redirects since each redirect may end up
// 		// modifying a pre-existing cookie.
// 		//
// 		// Since cookies already set in the request header do not contain
// 		// information about the original domain and path, the logic below
// 		// assumes any new set cookies override the original cookie
// 		// regardless of domain or path.
// 		//
// 		// See https://golang.org/issue/17494
// 		if c.Jar != nil && icookies != nil {
// 			var changed bool
// 			resp := req.Response // The response that caused the upcoming redirect
// 			for _, c := range resp.Cookies() {
// 				if _, ok := icookies[c.Name]; ok {
// 					delete(icookies, c.Name)
// 					changed = true
// 				}
// 			}
// 			if changed {
// 				ireqhdr.Del("Cookie")
// 				var ss []string
// 				for _, cs := range icookies {
// 					for _, c := range cs {
// 						ss = append(ss, c.Name+"="+c.Value)
// 					}
// 				}
// 				sort.Strings(ss) // Ensure deterministic headers
// 				ireqhdr.Set("Cookie", strings.Join(ss, "; "))
// 			}
// 		}

// 		// Copy the initial request's Header values
// 		// (at least the safe ones).
// 		for k, vv := range ireqhdr {
// 			if shouldCopyHeaderOnRedirect(k, preq.URL, req.URL) {
// 				req.Header[k] = vv
// 			}
// 		}

// 		preq = req // Update previous Request with the current request
// 	}
// }

// func defaultCheckRedirect(req *Request, via []*Request) error {
// 	if len(via) >= 10 {
// 		return errors.New("stopped after 10 redirects")
// 	}
// 	return nil
// }

// // Post issues a POST to the specified URL.
// //
// // Caller should close resp.Body when done reading from it.
// //
// // If the provided body is an io.Closer, it is closed after the
// // request.
// //
// // Post is a wrapper around DefaultClient.Post.
// //
// // To set custom headers, use NewRequest and DefaultClient.Do.
// //
// // See the Client.Do method documentation for details on how redirects
// // are handled.
// func Post(url, contentType string, body io.Reader) (resp *Response, err error) {
// 	return DefaultClient.Post(url, contentType, body)
// }

// // Post issues a POST to the specified URL.
// //
// // Caller should close resp.Body when done reading from it.
// //
// // If the provided body is an io.Closer, it is closed after the
// // request.
// //
// // To set custom headers, use NewRequest and Client.Do.
// //
// // See the Client.Do method documentation for details on how redirects
// // are handled.
// func (c *Client) Post(url, contentType string, body io.Reader) (resp *Response, err error) {
// 	req, err := NewRequest("POST", url, body)
// 	if err != nil {
// 		return nil, err
// 	}
// 	req.Header.Set("Content-Type", contentType)
// 	return c.Do(req)
// }

// // PostForm issues a POST to the specified URL, with data's keys and
// // values URL-encoded as the request body.
// //
// // The Content-Type header is set to application/x-www-form-urlencoded.
// // To set other headers, use NewRequest and DefaultClient.Do.
// //
// // When err is nil, resp always contains a non-nil resp.Body.
// // Caller should close resp.Body when done reading from it.
// //
// // PostForm is a wrapper around DefaultClient.PostForm.
// //
// // See the Client.Do method documentation for details on how redirects
// // are handled.
// func PostForm(url string, data url.Values) (resp *Response, err error) {
// 	return DefaultClient.PostForm(url, data)
// }

// // PostForm issues a POST to the specified URL,
// // with data's keys and values URL-encoded as the request body.
// //
// // The Content-Type header is set to application/x-www-form-urlencoded.
// // To set other headers, use NewRequest and Client.Do.
// //
// // When err is nil, resp always contains a non-nil resp.Body.
// // Caller should close resp.Body when done reading from it.
// //
// // See the Client.Do method documentation for details on how redirects
// // are handled.
// func (c *Client) PostForm(url string, data url.Values) (resp *Response, err error) {
// 	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
// }

// // Head issues a HEAD to the specified URL. If the response is one of
// // the following redirect codes, Head follows the redirect, up to a
// // maximum of 10 redirects:
// //
// //    301 (Moved Permanently)
// //    302 (Found)
// //    303 (See Other)
// //    307 (Temporary Redirect)
// //    308 (Permanent Redirect)
// //
// // Head is a wrapper around DefaultClient.Head
// func Head(url string) (resp *Response, err error) {
// 	return DefaultClient.Head(url)
// }

// // Head issues a HEAD to the specified URL. If the response is one of the
// // following redirect codes, Head follows the redirect after calling the
// // Client's CheckRedirect function:
// //
// //    301 (Moved Permanently)
// //    302 (Found)
// //    303 (See Other)
// //    307 (Temporary Redirect)
// //    308 (Permanent Redirect)
// func (c *Client) Head(url string) (resp *Response, err error) {
// 	req, err := NewRequest("HEAD", url, nil)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return c.Do(req)
// }

// // CloseIdleConnections closes any connections on its Transport which
// // were previously connected from previous requests but are now
// // sitting idle in a "keep-alive" state. It does not interrupt any
// // connections currently in use.
// //
// // If the Client's Transport does not have a CloseIdleConnections method
// // then this method does nothing.
// func (c *Client) CloseIdleConnections() {
// 	type closeIdler interface {
// 		CloseIdleConnections()
// 	}
// 	if tr, ok := c.transport().(closeIdler); ok {
// 		tr.CloseIdleConnections()
// 	}
// }

// // cancelTimerBody is an io.ReadCloser that wraps rc with two features:
// // 1) on Read error or close, the stop func is called.
// // 2) On Read failure, if reqDidTimeout is true, the error is wrapped and
// //    marked as net.Error that hit its timeout.
// type cancelTimerBody struct {
// 	stop          func() // stops the time.Timer waiting to cancel the request
// 	rc            io.ReadCloser
// 	reqDidTimeout func() bool
// }

// func (b *cancelTimerBody) Read(p []byte) (n int, err error) {
// 	n, err = b.rc.Read(p)
// 	if err == nil {
// 		return n, nil
// 	}
// 	b.stop()
// 	if err == io.EOF {
// 		return n, err
// 	}
// 	if b.reqDidTimeout() {
// 		err = &httpError{
// 			err:     err.Error() + " (Client.Timeout or context cancellation while reading body)",
// 			timeout: true,
// 		}
// 	}
// 	return n, err
// }

// func (b *cancelTimerBody) Close() error {
// 	err := b.rc.Close()
// 	b.stop()
// 	return err
// }

// func shouldCopyHeaderOnRedirect(headerKey string, initial, dest *url.URL) bool {
// 	switch CanonicalHeaderKey(headerKey) {
// 	case "Authorization", "Www-Authenticate", "Cookie", "Cookie2":
// 		// Permit sending auth/cookie headers from "foo.com"
// 		// to "sub.foo.com".

// 		// Note that we don't (send) all cookies to subdomains
// 		// automatically. This function is only used for
// 		// Cookies set explicitly on the initial outgoing
// 		// client request. Cookies automatically added via the
// 		// CookieJar mechanism continue to follow each
// 		// cookie's scope as set by Set-Cookie. But for
// 		// outgoing requests with the Cookie header set
// 		// directly, we don't know their scope, so we assume
// 		// it's for *.domain.com.

// 		ihost := canonicalAddr(initial)
// 		dhost := canonicalAddr(dest)
// 		return isDomainOrSubdomain(dhost, ihost)
// 	}
// 	// All other headers are copied:
// 	return true
// }

// // isDomainOrSubdomain reports whether sub is a subdomain (or exact
// // match) of the parent domain.
// //
// // Both domains must already be in canonical form.
// func isDomainOrSubdomain(sub, parent string) bool {
// 	if sub == parent {
// 		return true
// 	}
// 	// If sub is "foo.example.com" and parent is "example.com",
// 	// that means sub must end in "."+parent.
// 	// Do it without allocating.
// 	if !strings.HasSuffix(sub, parent) {
// 		return false
// 	}
// 	return sub[len(sub)-len(parent)-1] == '.'
// }

// func stripPassword(u *url.URL) string {
// 	_, passSet := u.User.Password()
// 	if passSet {
// 		return strings.Replace(u.String(), u.User.String()+"@", u.User.Username()+":***@", 1)
// 	}
// 	return u.String()
// }
