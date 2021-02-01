package main

import (
	"fmt"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

var CookieHandler = securecookie.New(securecookie.GenerateRandomKey(64),securecookie.GenerateRandomKey(32))

var store = sessions.NewCookieStore(securecookie.GenerateRandomKey(64))

func initialize() {
	store.Options = &sessions.Options{
		Domain:   "localhost",
		Path:     "/",
		MaxAge:   3600 * 8, // 8 hours
		HttpOnly: true,
	}
}

func main() {
	//initialize()
	router := ConfigureRouter()
	log.Fatal(http.ListenAndServe(":3001", handlers.LoggingHandler(os.Stdout, router)))
}

//ConfigureRouter setup the router
func ConfigureRouter() *mux.Router {
	router := mux.NewRouter()

	loginHandler := http.StripPrefix("/login", http.FileServer(http.Dir("./login/")))
	router.PathPrefix("/login").Handler(loginHandler)

	homePageHandler := http.StripPrefix("/home", http.FileServer(http.Dir("./home/")))
	//router.PathPrefix("/home").Handler(homePageHandler)

	router.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
        // You may check if a session exists here
        //userName := getUserName(r)
		session, _ := store.Get(r, "cookie-name")
		fmt.Println("session is", session)
		fmt.Println("session bool is", session.Values["authenticated"])
        if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", 302)
			return
		}
        //if userName == ""{
        //	fmt.Println("redirecting as the userName is not set")
        //    //http.Error(w, "you must login first", http.StatusUnauthorized)
        //	http.Redirect(w, r, "/login", 302)
        //    return
        //}
        //fmt.Println("userName is", userName)
        // Serve the requested file:
        homePageHandler.ServeHTTP(w, r)
    })

	router.HandleFunc("/", homeHandler)
	router.HandleFunc("/metacortex", metacortexHandler)
	router.HandleFunc("/agents/{name}", agentsHandler)

	router.HandleFunc("/authenticate", authenticateWithRedirect)

	router.Handle("/api/megacity", authMiddleware(megacityHandler))
	router.Handle("/api/levrai", authMiddleware(levraiHandler))

	return router
}

func loginHandler(response http.ResponseWriter, request *http.Request) {
	name := request.FormValue("name")
	pass := request.FormValue("password")
	redirectTarget := "/"
	if name != "" && pass != "" {
		// .. check credentials ..
		setSession(name, response)
		redirectTarget = "/home"
	}
	http.Redirect(response, request, redirectTarget, 302)
}

func logoutHandler(response http.ResponseWriter, request *http.Request) {
	clearSession(response)
	http.Redirect(response, request, "/login", 302)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the Matrix!"))
}
func metacortexHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Mr Anderson's not so secure workplace!"))
}
func agentsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("My name is agent " + vars["name"]))
}

var megacityHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the Megacity!"))
})

var levraiHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	name := r.Header.Get("name")
	if name != "neo" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Only Neo can enter the Merovingian's restaurant!"))
		return
	}
	w.Write([]byte("Welcome to the LeVrai!"))
})
