// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP Response reading and parsing.

package sip

import (
	"bufio"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

var respExcludeHeader = map[string]bool{
	"Content-Length": true,
}

// Response represents the response from an HTTP request.
//
// The Client and Transport return Responses from servers once
// the response headers have been received. The response body
// is streamed on demand as the Body field is read.
type Response struct {
	Status        string // e.g. "200 OK"
	StatusCode    int    // e.g. 200
	Proto         string // e.g. "HTTP/1.0"
	ProtoMajor    int    // e.g. 1
	ProtoMinor    int    // e.g. 0
	Header        http.Header
	Body          io.ReadCloser
	ContentLength int64
	Close         bool
	Request       *Request
}

// ReadResponse reads and returns an HTTP response from r.
// The req parameter optionally specifies the Request that corresponds
// to this Response. If nil, a GET request is assumed.
// Clients must call resp.Body.Close when finished reading resp.Body.
// After that call, clients can inspect resp.Trailer to find key/value
// pairs included in the response trailer.
func ReadResponse(r *bufio.Reader, req *Request) (*Response, error) {
	tp := textproto.NewReader(r)
	resp := &Response{
		Request: req,
	}

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if i := strings.IndexByte(line, ' '); i == -1 {
		return nil, badStringError("malformed HTTP response", line)
	} else {
		resp.Proto = line[:i]
		resp.Status = strings.TrimLeft(line[i+1:], " ")
	}
	statusCode := resp.Status
	if i := strings.IndexByte(resp.Status, ' '); i != -1 {
		statusCode = resp.Status[:i]
	}
	if len(statusCode) != 3 {
		return nil, badStringError("malformed HTTP status code", statusCode)
	}
	resp.StatusCode, err = strconv.Atoi(statusCode)
	if err != nil || resp.StatusCode < 0 {
		return nil, badStringError("malformed HTTP status code", statusCode)
	}
	var ok bool
	if resp.ProtoMajor, resp.ProtoMinor, ok = ParseSIPVersion(resp.Proto); !ok {
		return nil, badStringError("malformed HTTP version", resp.Proto)
	}

	// Parse the response headers.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = http.Header(mimeHeader)

	// fixPragmaCacheControl(resp.Header)

	// err = readTransfer(resp, r)
	// if err != nil {
	// 	return nil, err
	// }

	return resp, nil
}

// ProtoAtLeast reports whether the HTTP protocol used
// in the response is at least major.minor.
func (r *Response) ProtoAtLeast(major, minor int) bool {
	return r.ProtoMajor > major ||
		r.ProtoMajor == major && r.ProtoMinor >= minor
}

// Write writes r to w in the HTTP/1.x server response format,
// including the status line, headers, body, and optional trailer.
//
// This method consults the following fields of the response r:
//
//  StatusCode
//  ProtoMajor
//  ProtoMinor
//  Request.Method
//  TransferEncoding
//  Trailer
//  Body
//  ContentLength
//  Header, values for non-canonical keys will have unpredictable behavior
//
// The Response Body is closed after it is sent.
// func (r *Response) Write(w io.Writer) error {
// 	// Status line
// 	text := r.Status
// 	if text == "" {
// 		var ok bool
// 		text, ok = statusText[r.StatusCode]
// 		if !ok {
// 			text = "status code " + strconv.Itoa(r.StatusCode)
// 		}
// 	} else {
// 		// Just to reduce stutter, if user set r.Status to "200 OK" and StatusCode to 200.
// 		// Not important.
// 		text = strings.TrimPrefix(text, strconv.Itoa(r.StatusCode)+" ")
// 	}

// 	if _, err := fmt.Fprintf(w, "HTTP/%d.%d %03d %s\r\n", r.ProtoMajor, r.ProtoMinor, r.StatusCode, text); err != nil {
// 		return err
// 	}

// 	// Clone it, so we can modify r1 as needed.
// 	r1 := new(Response)
// 	*r1 = *r
// 	if r1.ContentLength == 0 && r1.Body != nil {
// 		// Is it actually 0 length? Or just unknown?
// 		var buf [1]byte
// 		n, err := r1.Body.Read(buf[:])
// 		if err != nil && err != io.EOF {
// 			return err
// 		}
// 		if n == 0 {
// 			// Reset it to a known zero reader, in case underlying one
// 			// is unhappy being read repeatedly.
// 			r1.Body = NoBody
// 		} else {
// 			r1.ContentLength = -1
// 			r1.Body = struct {
// 				io.Reader
// 				io.Closer
// 			}{
// 				io.MultiReader(bytes.NewReader(buf[:1]), r.Body),
// 				r.Body,
// 			}
// 		}
// 	}
// 	// If we're sending a non-chunked HTTP/1.1 response without a
// 	// content-length, the only way to do that is the old HTTP/1.0
// 	// way, by noting the EOF with a connection close, so we need
// 	// to set Close.
// 	if r1.ContentLength == -1 && !r1.Close && r1.ProtoAtLeast(1, 1) && !chunked(r1.TransferEncoding) && !r1.Uncompressed {
// 		r1.Close = true
// 	}

// 	// Process Body,ContentLength,Close,Trailer
// 	tw, err := newTransferWriter(r1)
// 	if err != nil {
// 		return err
// 	}
// 	err = tw.writeHeader(w, nil)
// 	if err != nil {
// 		return err
// 	}

// 	// Rest of header
// 	err = r.Header.WriteSubset(w, respExcludeHeader)
// 	if err != nil {
// 		return err
// 	}

// 	// contentLengthAlreadySent may have been already sent for
// 	// POST/PUT requests, even if zero length. See Issue 8180.
// 	contentLengthAlreadySent := tw.shouldSendContentLength()
// 	if r1.ContentLength == 0 && !chunked(r1.TransferEncoding) && !contentLengthAlreadySent && bodyAllowedForStatus(r.StatusCode) {
// 		if _, err := io.WriteString(w, "Content-Length: 0\r\n"); err != nil {
// 			return err
// 		}
// 	}

// 	// End-of-header
// 	if _, err := io.WriteString(w, "\r\n"); err != nil {
// 		return err
// 	}

// 	// Write body and trailer
// 	err = tw.writeBody(w)
// 	if err != nil {
// 		return err
// 	}

// 	// Success
// 	return nil
// }

func (r *Response) closeBody() {
	if r.Body != nil {
		r.Body.Close()
	}
}

// bodyIsWritable reports whether the Body supports writing. The
// Transport returns Writable bodies for 101 Switching Protocols
// responses.
// The Transport uses this method to determine whether a persistent
// connection is done being managed from its perspective. Once we
// return a writable response body to a user, the net/http package is
// done managing that connection.
func (r *Response) bodyIsWritable() bool {
	_, ok := r.Body.(io.Writer)
	return ok
}
