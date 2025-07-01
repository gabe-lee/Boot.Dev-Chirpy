package main

import (
	"log"
	"net/http"
)

func reportHealth(w http.ResponseWriter, req *http.Request) {
	contentType := "text/plain; charset=utf-8"
	contentTypeList := make([]string, 0, 1)
	contentTypeList = append(contentTypeList, contentType)
	req.Header["Content-Type"] = contentTypeList
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func main() {
	var mux = http.NewServeMux()
	var server = http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	mux.HandleFunc("/healthz", reportHealth)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal("%w", err)
	}
}
