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
	"time"

	"github.com/gabe-lee/Boot.Dev-Chirpy/internal/auth"
	"github.com/gabe-lee/Boot.Dev-Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const PORT = "8080"

var dbURL string
var jwtSecret string

type postChirpRequest struct {
	Body string `json:"body"`
}

type userLoginRequest struct {
	Pass  string `json:"password"`
	Email string `json:"email"`
}
type userLoginResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
	Refresh   string    `json:"refresh_token"`
}
type newUserRequest struct {
	Pass  string `json:"password"`
	Email string `json:"email"`
}

type tokenRefreshResponse struct {
	Token string `json:"token"`
}

var profanityWords = [...]string{
	"kerfuffle",
	"sharbert",
	"fornax",
}

func init() {
	godotenv.Load()
	dbURL = os.Getenv("DB_URL")
	jwtSecret = os.Getenv("JWT_SECRET")
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
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", app.deleteChirp())
	mux.HandleFunc("POST /api/users", app.addNewUser())
	mux.HandleFunc("PUT /api/users", app.updateUser())
	mux.HandleFunc("POST /api/login", app.loginUser())
	mux.HandleFunc("POST /api/refresh", app.refreshToken())
	mux.HandleFunc("POST /api/revoke", app.revokeToken())
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
		fmt.Fprintf(w, "{\n    \"error\": \"%s\"\n}", fmt.Sprintf(msgFmt, msgArgs...))
		return true
	}
	return false
}

func writeJsonErrorIfTrue(w http.ResponseWriter, cond bool, code int, msgFmt string, msgArgs ...any) bool {
	if cond {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, "{\n    \"error\": \"%s\"\n}", fmt.Sprintf(msgFmt, msgArgs...))
		return true
	}
	return false
}

func writeJsonErrorIfErrOrTrue(w http.ResponseWriter, err error, cond bool, code int, msgFmt string, msgArgs ...any) bool {
	if err != nil || cond {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, "{\n    \"error\": \"%s\"\n}", fmt.Sprintf(msgFmt, msgArgs...))
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
		token, err := auth.GetBearerToken(req.Header)
		if writeJsonErrorIfErr(w, err, 401, "Not logged in, cannot post Chirp") {
			return
		}
		tokenId, err := auth.ValidateJWT(token, jwtSecret)
		if writeJsonErrorIfErr(w, err, 401, "Token expired, please login again") {
			return
		}
		decoder := json.NewDecoder(req.Body)
		body := postChirpRequest{}
		err = decoder.Decode(&body)
		if writeJsonErrorIfErr(w, err, 500, "Error decoding json: %s", err) {
			return
		}
		if writeJsonErrorIfTrue(w, len(body.Body) > 140, 400, "Chirp is too long, max = 140 chars, recieved = %d chars", len(body.Body)) {
			return
		}
		cleanBody := replaceProfanity(body.Body)
		if writeJsonErrorIfErr(w, err, 400, "Invalid user_id UUID `%s` for Chirp: %s", tokenId, err) {
			return
		}
		chirp, err := state.db.PostChirp(req.Context(), database.PostChirpParams{
			Body:   cleanBody,
			UserID: tokenId,
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
		pass, err := auth.HashPassword(body.Pass)
		if writeJsonErrorIfErr(w, err, 500, "Error hashing password: %s", err) {
			return
		}
		user, err := state.db.CreateUser(req.Context(), database.CreateUserParams{
			Email:          body.Email,
			HashedPassword: pass,
		})
		if writeJsonErrorIfErr(w, err, 500, "Error adding new user: %s", err) {
			return
		}
		writeJson(w, 201, user)
	}
}

func (state *appState) loginUser() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		decoder := json.NewDecoder(req.Body)
		body := userLoginRequest{}
		err := decoder.Decode(&body)
		if writeJsonErrorIfErr(w, err, 500, "Error decoding json: %s", err) {
			return
		}
		user, err := state.db.FindUserByEmail(req.Context(), body.Email)
		if writeJsonErrorIfErr(w, err, 401, "Incorrect email or password") {
			return
		}
		err = auth.CheckPasswordHash(body.Pass, user.HashedPassword)
		if writeJsonErrorIfErr(w, err, 401, "Incorrect email or password") {
			return
		}
		token, err := auth.MakeJWT(user.ID, jwtSecret, time.Hour)
		if writeJsonErrorIfErr(w, err, 500, "Failed to create JWT token: %s", err) {
			return
		}
		refresh, _ := auth.MakeRefreshToken()
		err = state.db.NewRefresh(req.Context(), database.NewRefreshParams{
			Token:     refresh,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		})
		if writeJsonErrorIfErr(w, err, 500, "Failed to create Refresh token: %s", err) {
			return
		}
		userNoPass := userLoginResponse{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
			Token:     token,
			Refresh:   refresh,
		}
		writeJson(w, 200, userNoPass)
	}
}

func (state *appState) refreshToken() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		refresh, err := auth.GetBearerToken(req.Header)
		if writeJsonErrorIfErr(w, err, 400, "Failed to parse refresh token: %s", err) {
			return
		}
		revoked, err := state.db.CheckRevoke(req.Context(), refresh)
		if writeJsonErrorIfErrOrTrue(w, err, revoked.Valid, 401, "No Refresh token, please login first") {
			return
		}
		id, err := state.db.UpdateRefresh(req.Context(), database.UpdateRefreshParams{
			Token:     refresh,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		})
		if writeJsonErrorIfErr(w, err, 500, "Failed to update Refresh token: %s", err) {
			return
		}
		token, err := auth.MakeJWT(id, jwtSecret, time.Hour)
		if writeJsonErrorIfErr(w, err, 500, "Failed to create JWT token: %s", err) {
			return
		}
		writeJson(w, 200, tokenRefreshResponse{
			Token: token,
		})
	}
}

func (state *appState) revokeToken() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		refresh, err := auth.GetBearerToken(req.Header)
		if writeJsonErrorIfErr(w, err, 400, "Failed to parse refresh token: %s", err) {
			return
		}
		err = state.db.RevokeRefresh(req.Context(), refresh)
		if writeJsonErrorIfErr(w, err, 500, "failed to revoke Refresh token: %s", err) {
			return
		}
		w.WriteHeader(204)
	}
}

func (state *appState) updateUser() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		accessHeader, err := auth.GetBearerToken(req.Header)
		if writeJsonErrorIfErr(w, err, 401, "Failed to get access token from header: %s", err) {
			return
		}
		id, err := auth.ValidateJWT(accessHeader, jwtSecret)
		if writeJsonErrorIfErr(w, err, 401, "Failed to validate access token: %s", err) {
			return
		}
		decoder := json.NewDecoder(req.Body)
		newLogin := userLoginRequest{}
		err = decoder.Decode(&newLogin)
		if writeJsonErrorIfErr(w, err, 500, "Error decoding json: %s", err) {
			return
		}
		newPassHash, err := auth.HashPassword(newLogin.Pass)
		if writeJsonErrorIfErr(w, err, 500, "Error hashing password: %s", err) {
			return
		}
		user, err := state.db.UpdateLogin(req.Context(), database.UpdateLoginParams{
			ID:             id,
			Email:          newLogin.Email,
			HashedPassword: newPassHash,
		})
		if writeJsonErrorIfErr(w, err, 404, "user does not exist") {
			return
		}
		writeJson(w, 200, user)
	}
}

func (state *appState) deleteChirp() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		accessHeader, err := auth.GetBearerToken(req.Header)
		if writeJsonErrorIfErr(w, err, 401, "Failed to get access token from header: %s", err) {
			return
		}
		userId, err := auth.ValidateJWT(accessHeader, jwtSecret)
		if writeJsonErrorIfErr(w, err, 401, "Failed to validate access token: %s", err) {
			return
		}
		chirpIdStr := req.PathValue("chirpID")
		chirpId, err := uuid.Parse(chirpIdStr)
		if writeJsonErrorIfErr(w, err, 401, "Invalid chirp id `%s`", chirpIdStr) {
			return
		}
		author, err := state.db.GetChirpAuthor(req.Context(), chirpId)
		if writeJsonErrorIfErr(w, err, 404, "Chirp was not found using id `%s`", chirpIdStr) {
			return
		}
		if writeJsonErrorIfTrue(w, userId != author, 403, "You are not the author of this Chirp") {
			return
		}
		err = state.db.DeleteChirp(req.Context(), chirpId)
		if writeJsonErrorIfErr(w, err, 500, "failed to delete chirp: %s", err) {
			return
		}
		w.WriteHeader(204)
	}
}
