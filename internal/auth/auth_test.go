package auth

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

func TestBcryptValidPasses(t *testing.T) {
	cases := [...]string{
		"password",
		"123456",
		"",
		"102&^#^$(askda3a0rOIUDwidqwd738enjd",
		"(valid)",
	}
	for _, testcase := range cases {
		hash, err := HashPassword(testcase)
		if err != nil {
			t.Errorf("password `%s` failed to hash", testcase)
		}
		err = CheckPasswordHash(testcase, hash)
		if err != nil {
			t.Errorf("password `%s` didn't match its hash", testcase)
		}
	}
}

func TestBcryptInvalidFais(t *testing.T) {
	cases := [...]string{
		"password",
		"123456",
		"",
		"102&^#^$(askda3a0rOIUDwidqwd738enjd",
		"(valid)",
	}
	invhash, _ := HashPassword("(invalid)")
	for _, testcase := range cases {
		hash, err := HashPassword(testcase)
		if err != nil {
			t.Errorf("password `%s` failed to hash", testcase)
		}
		err = CheckPasswordHash("(invalid)", hash)
		if err == nil {
			t.Errorf("password `%s` hash matched with `(invalid)`", testcase)
		}
		err = CheckPasswordHash(testcase, invhash)
		if err == nil {
			t.Errorf("password `%s` matched with hash of `(invalid)`", testcase)
		}
	}
}

// func TestJWTValidPasses(t *testing.T) {
// 	jwtSecret := os.Getenv("JWT_SECRET")
// 	for range 10 {
// 		id, _ := uuid.NewRandom()
// 		token, err := MakeJWT(id, jwtSecret, time.Hour)
// 		if err != nil {
// 			t.Errorf("failed to make token with uuid `%s`: %s", id.String(), err)
// 		}
// 		outId, err := ValidateJWT(token, jwtSecret)
// 		if err != nil {
// 			t.Errorf("failed to extract uuid from valid token and secret: %s", err)
// 		}
// 		if id != outId {
// 			t.Errorf("extracted uuid from JWT didnt match the input uuid")
// 		}
// 	}
// }

// func TestJWTInvalidFails(t *testing.T) {
// 	jwtSecret := os.Getenv("JWT_SECRET")
// 	for range 10 {
// 		id, _ := uuid.NewRandom()
// 		token, err := MakeJWT(id, jwtSecret, time.Hour*-1)
// 		if err != nil {
// 			t.Errorf("failed to make token with uuid `%s`: %s", id.String(), err)
// 		}
// 		_, err = ValidateJWT(token, jwtSecret)
// 		if err == nil {
// 			t.Errorf("expected error (token expired), got nil error")
// 		}
// 	}
// }

func Test_JWT(t *testing.T) {
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	for range 10 {
		// Valid tokens
		id, _ := uuid.NewRandom()
		token, err := MakeJWT(id, jwtSecret, time.Hour)
		if err != nil {
			t.Errorf("failed to make token with uuid `%s`: %s", id.String(), err)
		}
		header := http.Header{}
		header.Add("Authorization", "Bearer "+token)
		extractedToken, err := GetBearerToken(header)
		if err != nil {
			t.Errorf("failed to extract token from `Authorization` header: %s", err)
		}
		outId, err := ValidateJWT(extractedToken, jwtSecret)
		if err != nil {
			t.Errorf("failed to extract uuid from valid token and secret: %s", err)
		}
		if id != outId {
			t.Errorf("extracted uuid from JWT didnt match the input uuid")
		}
		// Bad header
		header.Set("Authorization", "Bearer"+token)
		_, err = GetBearerToken(header)
		if err == nil {
			t.Errorf("expected error (malformed `Authorization` header), got nil error")
		}
		header.Del("Authorization")
		_, err = GetBearerToken(header)
		if err == nil {
			t.Errorf("expected error (missing `Authorization` header), got nil error")
		}
		// Expired tokens
		token, err = MakeJWT(id, jwtSecret, time.Hour*-1)
		if err != nil {
			t.Errorf("failed to make token with uuid `%s`: %s", id.String(), err)
		}
		_, err = ValidateJWT(token, jwtSecret)
		if err == nil {
			t.Errorf("expected error (token expired), got nil error")
		}
		// Bad secret tokens
		token, err = MakeJWT(id, jwtSecret, time.Hour)
		if err != nil {
			t.Errorf("failed to make token with uuid `%s`: %s", id.String(), err)
		}
		_, err = ValidateJWT(token, "oops")
		if err == nil {
			t.Errorf("expected error (mismatch secret key), got nil error")
		}
	}
}
