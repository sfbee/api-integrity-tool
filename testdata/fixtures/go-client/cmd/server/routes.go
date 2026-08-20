package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

// Every call in this file registers an inbound route. None of them is an
// outbound dependency, and confusing the two would fill the index with this
// repo's own API surface.
func routes() {
	http.HandleFunc("/api/v1/inbound", nil)

	m := mux.NewRouter()
	m.HandleFunc("/api/v1/mux-route", nil)

	g := gin.New()
	g.GET("/api/v1/gin-route", nil)
	g.POST("/api/v1/gin-route", nil)

	r := chi.NewRouter()
	r.Get("/api/v1/chi-route", func(w http.ResponseWriter, req *http.Request) {})
}
