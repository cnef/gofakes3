package gofakes3

import (
	"net/http"
	"strings"
)

const (
	signV4Algorithm = "AWS4-HMAC-SHA256"
	signV2Algorithm = "AWS"
)

// Credentials stores the information necessary to authorize with S3 and it
// is from this information that requests are signed.
type Credentials struct {
	AccessKey string
	SecretKey string
	PublicGet bool
}

// WithAuthRequire sets the auth credentials for enable authentication
// to check request header.
func WithAuthRequire(accessKey, secret string, publicGet bool) Option {

	if len(accessKey) == 0 || len(secret) == 0 {
		return func(g *GoFakeS3) {}
	}
	credentials := &Credentials{
		AccessKey: accessKey,
		SecretKey: secret,
		PublicGet: publicGet,
	}
	return func(g *GoFakeS3) { g.credentials = credentials }
}

func (g *GoFakeS3) authMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.allowPublicGet(r) || g.validSignVersion2(r) || g.validSignVersion4(r) {
			handler.ServeHTTP(w, r)
			return
		}
		g.httpError(w, r, requestUnauthorizedAccess())
	})
}

func (g *GoFakeS3) validSignVersion2(r *http.Request) bool {
	v2Auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(v2Auth, signV2Algorithm) ||
		strings.HasPrefix(v2Auth, signV4Algorithm) {
		return false
	}

	err := doesSignV2Match(r, *g.credentials)
	if err != nil {
		g.log.Print(LogErr, "signVersion2 failed:", err)
		return false
	}
	return true
}

func (g *GoFakeS3) validSignVersion4(r *http.Request) bool {
	authSign := r.Header.Get("Authorization")
	if !strings.HasPrefix(authSign, signV4Algorithm) {
		return false
	}

	checksum := getContentSha256Cksum(r)
	err := doesSignatureMatch(checksum, r, "", *g.credentials)
	if err != nil {
		g.log.Print(LogErr, "signVersion4 failed:", err)
		return false
	}

	return true
}

func (g *GoFakeS3) allowPublicGet(r *http.Request) bool {

	if !g.credentials.PublicGet {
		return false
	}

	var (
		path   = strings.Trim(r.URL.Path, "/")
		parts  = strings.SplitN(path, "/", 2)
		bucket = parts[0]
		query  = r.URL.Query()
		object = ""
	)

	if len(parts) == 2 {
		object = parts[1]
	}

	shouldAuthQuery := func() bool {
		for _, n := range resourceList {
			if _, ok := query[n]; ok {
				return true
			}
		}
		return false
	}
	if r.Method == http.MethodGet &&
		len(bucket) > 0 &&
		len(object) > 0 &&
		!shouldAuthQuery() {
		return true
	}

	return false
}

func requestUnauthorizedAccess() error {
	code := ErrUnauthorizedAccess
	return &ErrorResponse{
		Code:    code,
		Message: code.Message()}
}
