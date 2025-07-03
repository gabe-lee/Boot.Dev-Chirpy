package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/gabe-lee/Boot.Dev-Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const PORT = "8080"

var dbURL string

type postChirpRequest struct {
	Body   string `json:"body"`
	UserID string `json:"user_id"`
}

type newUserRequest struct {
	Email string `json:"email"`
}

var profanityWords = [...]string{
	"kerfuffle",
	"sharbert",
	"fornax",
}

func init() {
	godotenv.Load()
	dbURL = os.Getenv("DB_URL")
}

func main() {
	var mux = http.NewServeMux()
	var app = appState{}
	if os.Getenv("PLATFORM") == "dev" {
		app.is_dev_env = true
	}
	var server = http.Server{
		Addr:    ":" + PORT,
		Handler: mux,
	}
	mux.HandleFunc("/app/", app.increaseVisits(http.StripPrefix("/app", http.FileServer(http.Dir("./static"))).ServeHTTP))
	mux.HandleFunc("POST /admin/reset", app.checkIsDev(app.resetAppAndDatabase()))
	mux.HandleFunc("GET /admin/metrics", app.returnVisitCounter())
	mux.HandleFunc("GET /api/healthz", app.reportHealth)
	mux.HandleFunc("POST /api/chirps", app.postChirp())
	mux.HandleFunc("GET /api/chirps", app.getAllChirps())
	mux.HandleFunc("GET /api/chirps/{chirpID}", app.getChirp())
	mux.HandleFunc("POST /api/users", app.addNewUser())
	fmt.Printf("Server listening on port %s...", PORT)
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("%w", err)
	}
	app.db = database.New(db)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal("%w", err)
	}
}

func writeJson[T any](w http.ResponseWriter, code int, jsonStruct T) {
	w.Header().Set("Content-Type", "application/json")
	resJson, err := json.Marshal(jsonStruct)
	if err != nil {
		w.WriteHeader(500)
		log.Printf("Error marshalling JSON: %s", err)
		return
	}
	w.WriteHeader(code)
	_, err = w.Write(resJson)
	if err != nil {
		log.Printf("Error writing response: %s", err)
	}
}

func writeJsonErrorIfErr(w http.ResponseWriter, err error, code int, msgFmt string, msgArgs ...any) bool {
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, "{\n    error: \"%s\"\n}", fmt.Sprintf(msgFmt, msgArgs...))
		return true
	}
	return false
}

func writeJsonErrorIfTrue(w http.ResponseWriter, cond bool, code int, msgFmt string, msgArgs ...any) bool {
	if cond {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, "{\n    error: \"%s\"\n}", fmt.Sprintf(msgFmt, msgArgs...))
		return true
	}
	return false
}

type appState struct {
	visitCounter atomic.Int32
	db           *database.Queries
	is_dev_env   bool
}

func (*appState) reportHealth(w http.ResponseWriter, req *http.Request) {
	contentType := "text/plain; charset=utf-8"
	contentTypeList := make([]string, 0, 1)
	contentTypeList = append(contentTypeList, contentType)
	req.Header["Content-Type"] = contentTypeList
	w.WriteHeader(200)
	fmt.Fprint(w, "OK")
}

func (state *appState) getAllChirps() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		dbAllChirps, err := state.db.GetAllChirps(req.Context())
		if writeJsonErrorIfErr(w, err, 500, "Unable to get all chirps: %s", err) {
			return
		}
		writeJson(w, 200, dbAllChirps)
	}
}

func (state *appState) getChirp() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		chirpId := req.PathValue("chirpID")
		chirpUUID, err := uuid.Parse(chirpId)
		if writeJsonErrorIfErr(w, err, 400, "Invalid chirp id `%s`: %s", chirpId, err) {
			return
		}
		chirp, err := state.db.GetChirp(req.Context(), chirpUUID)
		if writeJsonErrorIfErr(w, err, 404, "Unable to find chirp: %s", err) {
			return
		}
		writeJson(w, 200, chirp)
	}
}

func (state *appState) postChirp() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		decoder := json.NewDecoder(req.Body)
		body := postChirpRequest{}
		err := decoder.Decode(&body)
		if writeJsonErrorIfErr(w, err, 500, "Error decoding json: %s", err) {
			return
		}
		if writeJsonErrorIfTrue(w, len(body.Body) > 140, 400, "Chirp is too long, max = 140, recieved = %d", len(body.Body)) {
			return
		}
		cleanBody := replaceProfanity(body.Body)
		userId, err := uuid.Parse(body.UserID)
		if writeJsonErrorIfErr(w, err, 400, "Invalid user_id UUID `%s` for Chirp: %s", body.UserID, err) {
			return
		}
		chirp, err := state.db.PostChirp(req.Context(), database.PostChirpParams{
			Body:   cleanBody,
			UserID: userId,
		})
		if writeJsonErrorIfErr(w, err, 500, "Unable to post chirp: %s", err) {
			return
		}
		writeJson(w, 201, chirp)
	}
}

func replaceProfanity(input string) string {
	var words = strings.Split(input, " ")
	for i, word := range words {
		var lower = strings.ToLower(word)
		for _, profane := range profanityWords {
			if lower == profane {
				words[i] = "****"
			}
		}
	}
	return strings.Join(words, " ")
}

func (state *appState) checkIsDev(next func(w http.ResponseWriter, req *http.Request)) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if writeJsonErrorIfTrue(w, !state.is_dev_env, 403, "You do not have persmission to execute this command") {
			return
		}
		next(w, req)
	}
}

func (state *appState) increaseVisits(next func(w http.ResponseWriter, req *http.Request)) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		state.visitCounter.Add(1)
		next(w, req)
	}
}

func (state *appState) returnVisitCounter() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		visits := state.visitCounter.Load()
		contentType := "text/html; charset=utf-8"
		contentTypeList := make([]string, 0, 1)
		contentTypeList = append(contentTypeList, contentType)
		req.Header["Content-Type"] = contentTypeList
		w.WriteHeader(200)
		fmt.Fprintf(w, `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, visits)
	}
}

func (state *appState) resetAppAndDatabase() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		state.visitCounter.Store(0)
		state.db.DeleteAllUsers(req.Context())
		w.WriteHeader(200)
	}
}

func (state *appState) addNewUser() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		decoder := json.NewDecoder(req.Body)
		body := newUserRequest{}
		err := decoder.Decode(&body)
		if writeJsonErrorIfErr(w, err, 500, "Error decoding json: %s", err) {
			return
		}
		user, err := state.db.CreateUser(req.Context(), body.Email)
		if writeJsonErrorIfErr(w, err, 500, "Error adding new user: %s", err) {
			return
		}
		writeJson(w, 201, user)
	}
}
