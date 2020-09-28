package main


import (
  "github.com/gorilla/mux"
  "log"
  "net/http"
  "time"
  "encoding/json"
  "os"

  "github.com/oauth2-proxy/oauth2-proxy/pkg/middleware"
  "github.com/oauth2-proxy/oauth2-proxy/pkg/sessions"
  "github.com/oauth2-proxy/oauth2-proxy/providers"
  oauth2options "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
  "github.com/justinas/alice"
)

var (
  cookieName = "_oauth2_proxy"
)

// Logging ...
// log the HTTP requests
func Logging(next http.Handler) http.Handler {
  // log all requests
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    jsonEncodedRequest, err := json.Marshal(r.Header)
    if err != nil {
      log.Panicln(err)
    }
    c, err := r.Cookie(cookieName)
    log.Printf("cookie: %v; err: %v\n", c, err)
    log.Printf("%v", string(jsonEncodedRequest))
    next.ServeHTTP(w, r)
  })
}

// Root ...
// /api endpoint
func Root(w http.ResponseWriter, r *http.Request) {
  w.WriteHeader(http.StatusOK)
  w.Write([]byte("Headers logged"))
}

func main() {
  port := ":8085"
  router := mux.NewRouter().StrictSlash(true)
  router.HandleFunc("/", Root)

  authSecret := os.Getenv("APP_OAUTH2_SECRET")
  log.Printf("authSecret: %v\n", authSecret)
  cookieOptions := oauth2options.Cookie{
    Name: cookieName,
    Secret: authSecret,
  }
  sessionOptions := oauth2options.SessionOptions{
    Type: oauth2options.CookieSessionStoreType,
  }
  sessionStore, err := sessions.NewSessionStore(&sessionOptions, &cookieOptions)
  if err != nil {
    log.Println(err)
    return
  }
	// TODO sync the session with oauth2-proxy
  storedSessionOptions := middleware.StoredSessionLoaderOptions{
    SessionStore: sessionStore,
    RefreshPeriod: time.Duration(0),
    // RefreshSessionIfNeeded: ,
    // ValidateSessionState: ,
  }
  chain := alice.New()
  chain = chain.Append(Logging, middleware.NewScope(), middleware.NewStoredSessionLoader(&storedSessionOptions))

  srv := &http.Server{
    Handler:      chain.Then(router),
    Addr:         port,
    WriteTimeout: 15 * time.Second,
    ReadTimeout:  15 * time.Second,
  }
  log.Println("HTTP listening on", port)
  log.Fatal(srv.ListenAndServe())
}
