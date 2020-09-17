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
  oauth2options "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
  "github.com/justinas/alice"
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
    Name: "_oauth2_proxy",
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
  storedSessionOptions := middleware.StoredSessionLoaderOptions{
    SessionStore: sessionStore,
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
