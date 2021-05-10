// Test cookie decryption


package main


import (
  "github.com/gorilla/mux"
  "log"
  "encoding/base64"
  "net/http"
  "time"
  "encoding/json"
  "strings"
  "os"
  "fmt"

  "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
  "github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
)

var (
  defaultOAuthCookieName = "_oauth2_proxy"
  maxCookieLength = 4000
)

// splitCookie reads the full cookie generated to store the session and splits
// it into a slice of cookies which fit within the 4kb cookie limit indexing
// the cookies from 0
func splitCookie(c *http.Cookie) []*http.Cookie {
 if len(c.String()) < maxCookieLength {
  return []*http.Cookie{c}
 }

 log.Printf("WARNING: Multiple cookies are required for this session as it exceeds the 4kb cookie limit. Please use server side session storage (eg. Redis) instead.")

 cookies := []*http.Cookie{}
 valueBytes := []byte(c.Value)
 count := 0
 for len(valueBytes) > 0 {
  newCookie := copyCookie(c)
  newCookie.Name = splitCookieName(c.Name, count)
  count++

  newCookie.Value = string(valueBytes)
  cookieLength := len(newCookie.String())
  if cookieLength <= maxCookieLength {
   valueBytes = []byte{}
  } else {
   overflow := cookieLength - maxCookieLength
   valueSize := len(valueBytes) - overflow

   newValue := valueBytes[:valueSize]
   valueBytes = valueBytes[valueSize:]
   newCookie.Value = string(newValue)
  }
  cookies = append(cookies, newCookie)
 }
 return cookies
}

func splitCookieName(name string, count int) string {
 splitName := fmt.Sprintf("%s_%d", name, count)
 overflow := len(splitName) - 256
 if overflow > 0 {
  splitName = fmt.Sprintf("%s_%d", name[:len(name)-overflow], count)
 }
 return splitName
}

// loadCookie retreieves the sessions state cookie from the http request.
// If a single cookie is present this will be returned, otherwise it attempts
// to reconstruct a cookie split up by splitCookie
func loadCookie(req *http.Request, cookieName string) (*http.Cookie, error) {
 c, err := req.Cookie(cookieName)
 if err == nil {
  return c, nil
 }
 cookies := []*http.Cookie{}
 err = nil
 count := 0
 for err == nil {
  var c *http.Cookie
  c, err = req.Cookie(splitCookieName(cookieName, count))
  if err == nil {
   cookies = append(cookies, c)
   count++
  }
 }
 if len(cookies) == 0 {
  return nil, fmt.Errorf("could not find cookie %s", cookieName)
 }
 return joinCookies(cookies)
}

// joinCookies takes a slice of cookies from the request and reconstructs the
// full session cookie
func joinCookies(cookies []*http.Cookie) (*http.Cookie, error) {
 if len(cookies) == 0 {
  return nil, fmt.Errorf("list of cookies must be > 0")
 }
 if len(cookies) == 1 {
  return cookies[0], nil
 }
 c := copyCookie(cookies[0])
 for i := 1; i < len(cookies); i++ {
  c.Value += cookies[i].Value
 }
 c.Name = strings.TrimRight(c.Name, "_0")
 return c, nil
}

func copyCookie(c *http.Cookie) *http.Cookie {
 return &http.Cookie{
  Name:       c.Name,
  Value:      c.Value,
  Path:       c.Path,
  Domain:     c.Domain,
  Expires:    c.Expires,
  RawExpires: c.RawExpires,
  MaxAge:     c.MaxAge,
  Secure:     c.Secure,
  HttpOnly:   c.HttpOnly,
  Raw:        c.Raw,
  Unparsed:   c.Unparsed,
  SameSite:   c.SameSite,
 }
}

// Logging ...
// log the HTTP requests
func Logging(next http.Handler) http.Handler {
  // log all requests
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    jsonEncodedRequest, err := json.Marshal(r.Header)
    if (err != nil) {
      log.Panicln(err)
    }
    log.Printf("%v", string(jsonEncodedRequest))
    next.ServeHTTP(w, r)
  })
}

// Root ...
// /api endpoint
func Root(w http.ResponseWriter, r *http.Request) {
  authSecret := os.Getenv("APP_OAUTH2_SECRET")
  log.Printf("authSecret: %v\n", authSecret)

  w.WriteHeader(http.StatusOK)
  w.Write([]byte("Headers logged"))
  cookie, err := loadCookie(r, defaultOAuthCookieName)
  if err != nil {
    // always http.ErrNoCookie
    fmt.Errorf("cookie %q not present", defaultOAuthCookieName)
    return
  }
  parts := strings.Split(cookie.Value, "|")
  log.Println(parts[0])
  value, err := base64.URLEncoding.DecodeString(parts[0])
  if err != nil {
    log.Printf("%#v\n", err)
    return
  }
  log.Printf("%#v\n", string(value))

  cipher, err := encryption.NewCFBCipher([]byte(authSecret))
  if err != nil {
    log.Printf("%#v\n", err)
    return
  }
  session, err := sessions.DecodeSessionState(value, cipher, true)
  if err != nil {
    log.Printf("%v\n", err)
	  return
  }
  log.Println(session.User)
}

func main() {
  port := ":8085"
  router := mux.NewRouter().StrictSlash(true)
  router.HandleFunc("/", Root)
  router.Use(Logging)
  srv := &http.Server{
    Handler:      router,
    Addr:         port,
    WriteTimeout: 15 * time.Second,
    ReadTimeout:  15 * time.Second,
  }
  log.Println("HTTP listening on", port)
  log.Fatal(srv.ListenAndServe())
}
