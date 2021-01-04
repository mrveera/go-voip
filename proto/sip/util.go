package sip

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
)

func WwwDigest(username string, realm string, password string, method string, uri string, nonce string) string {
	calcA1 := func() string {
		encoder := md5.New()
		encoder.Write([]byte(username + ":" + realm + ":" + password))

		return hex.EncodeToString(encoder.Sum(nil))
	}
	calcA2 := func() string {
		encoder := md5.New()
		encoder.Write([]byte(method + ":" + uri))

		return hex.EncodeToString(encoder.Sum(nil))
	}

	encoder := md5.New()
	encoder.Write([]byte(calcA1() + ":" + nonce + ":" + calcA2()))

	return hex.EncodeToString(encoder.Sum(nil))
}

func GetFromAuthz(header string, key string) string {
	parts := strings.SplitN(header, " ", 2)
	parts = strings.Split(parts[1], ",")
	opts := make(map[string]string)

	for _, part := range parts {
		vals := strings.SplitN(part, "=", 2)
		key := vals[0]
		val := strings.Trim(vals[1], "\",")
		opts[key] = val
	}
	return opts[key]
}

func GetRealm(authz string) string {
	return GetFromAuthz(authz, "realm")
}

func GetNonce(authz string) string {
	return GetFromAuthz(authz, "nonce")
}
