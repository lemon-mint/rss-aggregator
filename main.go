package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/feeds"
	"github.com/julienschmidt/httprouter"
	"github.com/mmcdole/gofeed"
	"gopkg.eu.org/envloader"

	"github.com/lemon-mint/rss-aggregator/database"
	"github.com/lemon-mint/rss-aggregator/database/passhash"
)

var pid = os.Getpid()

func init() {
	go func() {
		for {
			ppid := os.Getppid()
			if ppid == 1 {
				// send sigterm to self
				cmd := exec.Command("kill", "-TERM", strconv.Itoa(pid))
				cmd.Run()
				time.Sleep(time.Second * 60)
				os.Exit(1)
			}
			time.Sleep(time.Second * 1)
		}
	}()
}

//go:embed views
var viewsFS embed.FS

type Server struct {
	db      *sql.DB
	queries *database.Queries
	router  *httprouter.Router
	fp      *gofeed.Parser
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AddFeedRequest struct {
	URL    string `json:"url"`
	ViewID int64  `json:"viewId"`
}

type CreateViewRequest struct {
	Name   string `json:"name"`
	Public bool   `json:"public"`
}

func init() {
	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	// Pretty print logs to console
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	})
}

func generateSlug() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	log.Error().
		Int("code", code).
		Str("msg", msg).
		Str("type", "error_response").
		Msg("Responding with error")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Error: msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	log.Debug().
		Int("code", code).
		Interface("payload", payload).
		Str("type", "json_response").
		Msg("Responding with JSON")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

type contextKey string

const userIDKey contextKey = "user_id"

func (s *Server) authMiddleware(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		logger := log.With().
			Str("path", r.URL.Path).
			Str("method", r.Method).
			Logger()

		logger.Debug().Msg("Starting auth middleware")

		path := r.URL.Path
		// Skip auth for login, register, and public feed endpoints
		if path == "/api/login" || path == "/api/register" || strings.HasPrefix(path, "/feed/") {
			logger.Debug().Msg("Skipping auth for public endpoint")
			next(w, r, ps)
			return
		}

		// Check session token
		sessionToken := r.Header.Get("Authorization")
		if sessionToken == "" {
			cookie, err := r.Cookie("session_token")
			if err != nil {
				logger.Warn().Err(err).Msg("No session token found")
				http.Redirect(w, r, "/login.html", http.StatusSeeOther)
				return
			}
			sessionToken = cookie.Value
		}

		session, err := s.queries.GetSessionByToken(r.Context(), sessionToken)
		if err != nil {
			logger.Warn().
				Err(err).
				Str("sessionToken", sessionToken).
				Msg("Invalid session token")
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}

		logger.Debug().
			Int64("userID", session.UserID).
			Msg("User authenticated successfully")

		// Store user ID in context
		ctx := context.WithValue(r.Context(), userIDKey, session.UserID)
		next(w, r.WithContext(ctx), ps)
	}
}

func NewServer(db *sql.DB) *Server {
	log.Info().Msg("Creating new server instance")
	s := &Server{
		db:      db,
		queries: database.New(db),
		router:  httprouter.New(),
		fp:      gofeed.NewParser(),
	}

	staticFS, err := fs.Sub(viewsFS, "views")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create static FS")
	}

	s.router.NotFound = http.FileServer(http.FS(staticFS))

	// Auth routes
	s.router.POST("/api/login", s.handleLogin)
	s.router.POST("/api/register", s.handleRegister)

	// Protected routes
	s.router.GET("/api/views", s.authMiddleware(s.handleGetViews))
	s.router.POST("/api/views", s.authMiddleware(s.handleCreateView))
	s.router.DELETE("/api/views/:id", s.authMiddleware(s.handleDeleteView))
	s.router.GET("/api/views/:id/feeds", s.authMiddleware(s.handleGetViewFeeds))
	s.router.DELETE("/api/views/:id/feeds/:feedId", s.authMiddleware(s.handleRemoveFeedFromView))

	s.router.POST("/api/feeds", s.authMiddleware(s.handleAddFeed))

	// Public routes
	s.router.GET("/feed/:slug", s.handleGetFeed)

	log.Info().Msg("Server routes configured successfully")
	return s
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	logger := log.With().Str("handler", "login").Logger()
	logger.Debug().Msg("Processing login request")

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().Err(err).Msg("Invalid request payload")
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	user, err := s.queries.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		logger.Warn().
			Err(err).
			Str("email", req.Email).
			Msg("User not found")
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if ok, _ := passhash.VerifyPassHash(req.Password, user.Password); !ok {
		logger.Warn().
			Str("email", req.Email).
			Msg("Invalid password attempt")
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Create session
	sessionToken := generateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = s.queries.CreateSession(r.Context(), database.CreateSessionParams{
		UserID:    user.ID,
		Token:     sessionToken,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		logger.Error().
			Err(err).
			Str("email", req.Email).
			Msg("Failed to create session")
		respondWithError(w, http.StatusInternalServerError, "Could not create session")
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiresAt,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	logger.Info().
		Str("email", req.Email).
		Int64("userID", user.ID).
		Msg("Login successful")
	respondWithJSON(w, http.StatusOK, user)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	logger := log.With().Str("handler", "register").Logger()
	logger.Debug().Msg("Processing register request")

	if os.Getenv("DISABLE_REGISTRATION") == "true" {
		logger.Warn().Msg("Registration is disabled")
		respondWithError(w, http.StatusForbidden, "Registration is disabled")
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().Err(err).Msg("Invalid request payload")
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validate email
	req.Email = strings.TrimSpace(req.Email)
	req.Email = strings.ToLower(req.Email)
	if strings.Count(req.Email, "@") != 1 {
		logger.Warn().
			Str("email", req.Email).
			Msg("Invalid email address")
		respondWithError(w, http.StatusBadRequest, "Invalid email address")
		return
	}

	// Validate password
	if len(req.Password) < 8 {
		logger.Warn().
			Str("email", req.Email).
			Msg("Password must be at least 8 characters long")
		respondWithError(w, http.StatusBadRequest, "Password must be at least 8 characters long")
		return
	}

	hashedPassword := passhash.NewPassHash(req.Password)

	result, err := s.queries.CreateUser(r.Context(), database.CreateUserParams{
		Email:    req.Email,
		Password: string(hashedPassword),
	})
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			logger.Warn().
				Str("email", req.Email).
				Msg("Email already exists")
			respondWithError(w, http.StatusConflict, "Email already exists")
			return
		}
		logger.Error().
			Err(err).
			Str("email", req.Email).
			Msg("Failed to create user")
		respondWithError(w, http.StatusInternalServerError, "Could not create user")
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		logger.Error().
			Err(err).
			Str("email", req.Email).
			Msg("Failed to get user ID")
		respondWithError(w, http.StatusInternalServerError, "Could not create user")
		return
	}

	// Create session
	sessionToken := generateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = s.queries.CreateSession(r.Context(), database.CreateSessionParams{
		UserID:    id,
		Token:     sessionToken,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		logger.Error().
			Err(err).
			Str("email", req.Email).
			Msg("Failed to create session")
		respondWithError(w, http.StatusInternalServerError, "Could not create session")
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiresAt,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	logger.Info().
		Str("email", req.Email).
		Int64("userID", id).
		Msg("Registration successful")
	respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"id":    id,
		"email": req.Email,
	})
}

func (s *Server) handleGetViews(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	logger := log.With().Str("handler", "getViews").Logger()
	logger.Debug().Msg("Processing get views request")

	userID := r.Context().Value(userIDKey).(int64)
	views, err := s.queries.GetUserViews(r.Context(), userID)
	if err != nil {
		logger.Error().
			Err(err).
			Int64("userID", userID).
			Msg("Failed to get views")
		respondWithError(w, http.StatusInternalServerError, "Could not get views")
		return
	}

	logger.Debug().
		Int64("userID", userID).
		Int("viewCount", len(views)).
		Msg("Retrieved user views")
	respondWithJSON(w, http.StatusOK, views)
}

func (s *Server) handleCreateView(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	logger := log.With().Str("handler", "createView").Logger()
	logger.Debug().Msg("Processing create view request")

	var req CreateViewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().Err(err).Msg("Invalid request payload")
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	userID := r.Context().Value(userIDKey).(int64)

	tx, err := s.db.Begin()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to begin transaction")
		respondWithError(w, http.StatusInternalServerError, "Could not create view")
		return
	}
	defer tx.Rollback()

	txq := s.queries.WithTx(tx)

	result, err := txq.CreateView(r.Context(), database.CreateViewParams{
		Name:   req.Name,
		Public: req.Public,
		Slug:   generateSlug(),
	})
	if err != nil {
		logger.Error().
			Err(err).
			Str("viewName", req.Name).
			Msg("Failed to create view")
		respondWithError(w, http.StatusInternalServerError, "Could not create view")
		return
	}

	viewID, _ := result.LastInsertId()

	err = txq.CreateUserView(r.Context(), database.CreateUserViewParams{
		UserID: userID,
		ViewID: viewID,
	})
	if err != nil {
		logger.Error().
			Err(err).
			Int64("userID", userID).
			Int64("viewID", viewID).
			Msg("Failed to create user view")
		respondWithError(w, http.StatusInternalServerError, "Could not create user view")
		return
	}

	err = tx.Commit()
	if err != nil {
		logger.Error().
			Err(err).
			Int64("viewID", viewID).
			Msg("Failed to commit transaction")
		respondWithError(w, http.StatusInternalServerError, "Could not commit transaction")
		return
	}

	logger.Info().
		Int64("viewID", viewID).
		Str("viewName", req.Name).
		Bool("public", req.Public).
		Msg("View created successfully")
	respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"id":     viewID,
		"name":   req.Name,
		"public": req.Public,
	})
}

func (s *Server) handleDeleteView(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	logger := log.With().Str("handler", "deleteView").Logger()
	logger.Debug().Msg("Processing delete view request")

	viewID := ps.ByName("id")
	if viewID == "" {
		logger.Warn().Msg("Invalid view ID provided")
		respondWithError(w, http.StatusBadRequest, "Invalid view ID")
		return
	}

	id, err := strconv.ParseInt(viewID, 10, 64)
	if err != nil {
		logger.Warn().
			Err(err).
			Str("viewID", viewID).
			Msg("Invalid view ID format")
		respondWithError(w, http.StatusBadRequest, "Invalid view ID format")
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to begin transaction")
		respondWithError(w, http.StatusInternalServerError, "Could not delete view")
		return
	}

	txq := s.queries.WithTx(tx)

	view_feeds, err := txq.GetViewFeeds(r.Context(), id)
	if err != nil {
		logger.Error().
			Err(err).
			Int64("viewID", id).
			Msg("Failed to get view feeds")
		respondWithError(w, http.StatusInternalServerError, "Could not delete view")
		return
	}

	for _, feed := range view_feeds {
		err = txq.DecrementFeedRefCount(r.Context(), feed.ID)
		if err != nil {
			logger.Error().
				Err(err).
				Int64("feedID", feed.ID).
				Msg("Failed to decrement feed ref count")
			respondWithError(w, http.StatusInternalServerError, "Could not delete view")
			return
		}

		refcount, err := txq.GetFeedRefCount(r.Context(), feed.ID)
		if err != nil {
			logger.Error().
				Err(err).
				Int64("feedID", feed.ID).
				Msg("Failed to get feed ref count")
			respondWithError(w, http.StatusInternalServerError, "Could not delete view")
			return
		}

		if refcount <= 0 {
			err = txq.DeleteFeed(r.Context(), feed.ID)
			if err != nil {
				logger.Error().
					Err(err).
					Int64("feedID", feed.ID).
					Msg("Failed to delete feed")
				respondWithError(w, http.StatusInternalServerError, "Could not delete view")
				return
			}
		}
	}

	err = txq.DeleteView(r.Context(), id)
	if err != nil {
		logger.Error().
			Err(err).
			Int64("viewID", id).
			Msg("Failed to delete view")
		respondWithError(w, http.StatusInternalServerError, "Could not delete view")
		return
	}

	logger.Info().
		Int64("viewID", id).
		Msg("View deleted successfully")
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGetViewFeeds(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	logger := log.With().Str("handler", "getViewFeeds").Logger()
	logger.Debug().Msg("Processing get view feeds request")

	viewID := ps.ByName("id")
	if viewID == "" {
		logger.Warn().Msg("Invalid view ID provided")
		respondWithError(w, http.StatusBadRequest, "Invalid view ID")
		return
	}

	id, err := strconv.ParseInt(viewID, 10, 64)
	if err != nil {
		logger.Warn().
			Err(err).
			Str("viewID", viewID).
			Msg("Invalid view ID format")
		respondWithError(w, http.StatusBadRequest, "Invalid view ID format")
		return
	}

	feeds, err := s.queries.GetViewFeeds(r.Context(), id)
	if err != nil {
		logger.Error().
			Err(err).
			Int64("viewID", id).
			Msg("Failed to get feeds")
		respondWithError(w, http.StatusInternalServerError, "Could not get feeds")
		return
	}

	logger.Debug().
		Int64("viewID", id).
		Int("feedCount", len(feeds)).
		Msg("Retrieved view feeds")
	respondWithJSON(w, http.StatusOK, feeds)
}

func (s *Server) handleAddFeed(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	logger := log.With().Str("handler", "addFeed").Logger()
	logger.Debug().Msg("Processing add feed request")

	var req AddFeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().Err(err).Msg("Invalid request payload")
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Check if feed already exists
	existingFeed, err := s.queries.GetFeedByURL(r.Context(), req.URL)
	var feedID int64

	if err == sql.ErrNoRows {
		// Feed doesn't exist, create it
		feed, err := s.fp.ParseURL(req.URL)
		if err != nil {
			logger.Error().
				Err(err).
				Str("url", req.URL).
				Msg("Failed to parse feed")
			respondWithError(w, http.StatusBadRequest, "Could not parse feed")
			return
		}

		result, err := s.queries.CreateFeed(r.Context(), database.CreateFeedParams{
			Title: feed.Title,
			Url:   req.URL,
		})
		if err != nil {
			logger.Error().
				Err(err).
				Str("url", req.URL).
				Msg("Failed to create feed")
			respondWithError(w, http.StatusInternalServerError, "Could not create feed")
			return
		}

		feedID, _ = result.LastInsertId()
		logger.Info().
			Int64("feedID", feedID).
			Str("url", req.URL).
			Msg("New feed created")
	} else if err != nil {
		logger.Error().
			Err(err).
			Str("url", req.URL).
			Msg("Failed to check feed existence")
		respondWithError(w, http.StatusInternalServerError, "Could not check feed existence")
		return
	} else {
		// Feed exists, use its ID
		feedID = existingFeed.ID
		logger.Debug().
			Int64("feedID", feedID).
			Str("url", req.URL).
			Msg("Using existing feed")
	}

	// Add feed to view
	err = s.queries.AddFeedToView(r.Context(), database.AddFeedToViewParams{
		ViewID: req.ViewID,
		FeedID: feedID,
	})
	if err != nil {
		logger.Error().
			Err(err).
			Int64("feedID", feedID).
			Int64("viewID", req.ViewID).
			Msg("Failed to add feed to view")
		respondWithError(w, http.StatusInternalServerError, "Could not add feed to view")
		return
	}

	logger.Info().
		Int64("feedID", feedID).
		Int64("viewID", req.ViewID).
		Msg("Feed added to view successfully")
	respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"id":     feedID,
		"viewId": req.ViewID,
	})
}

func (s *Server) handleRemoveFeedFromView(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	logger := log.With().Str("handler", "removeFeedFromView").Logger()
	logger.Debug().Msg("Processing remove feed from view request")

	viewID, err := strconv.ParseInt(ps.ByName("id"), 10, 64)
	if err != nil {
		logger.Warn().
			Err(err).
			Str("viewID", ps.ByName("id")).
			Msg("Invalid view ID")
		respondWithError(w, http.StatusBadRequest, "Invalid view ID")
		return
	}

	feedID, err := strconv.ParseInt(ps.ByName("feedId"), 10, 64)
	if err != nil {
		logger.Warn().
			Err(err).
			Str("feedID", ps.ByName("feedId")).
			Msg("Invalid feed ID")
		respondWithError(w, http.StatusBadRequest, "Invalid feed ID")
		return
	}

	// Start transaction
	tx, err := s.db.Begin()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to begin transaction")
		respondWithError(w, http.StatusInternalServerError, "Could not process request")
		return
	}
	defer tx.Rollback()

	txq := s.queries.WithTx(tx)

	// Remove feed from view
	err = txq.RemoveFeedFromView(r.Context(), database.RemoveFeedFromViewParams{
		ViewID: viewID,
		FeedID: feedID,
	})
	if err != nil {
		logger.Error().
			Err(err).
			Int64("viewID", viewID).
			Int64("feedID", feedID).
			Msg("Failed to remove feed from view")
		respondWithError(w, http.StatusInternalServerError, "Could not remove feed from view")
		return
	}

	// Decrement reference count and get new count
	err = txq.DecrementFeedRefCount(r.Context(), feedID)
	if err != nil {
		logger.Error().
			Err(err).
			Int64("feedID", feedID).
			Msg("Failed to decrement feed reference count")
		respondWithError(w, http.StatusInternalServerError, "Could not update feed reference count")
		return
	}

	refCount, err := txq.GetFeedRefCount(r.Context(), feedID)
	if err != nil {
		logger.Error().
			Err(err).
			Int64("feedID", feedID).
			Msg("Failed to get feed reference count")
		respondWithError(w, http.StatusInternalServerError, "Could not update feed reference count")
		return
	}

	// If reference count is 0, delete the feed
	if refCount <= 0 {
		err = txq.DeleteFeed(r.Context(), feedID)
		if err != nil {
			logger.Error().
				Err(err).
				Int64("feedID", feedID).
				Msg("Failed to delete feed")
			respondWithError(w, http.StatusInternalServerError, "Could not delete feed")
			return
		}
		logger.Info().
			Int64("feedID", feedID).
			Msg("Feed deleted due to zero references")
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		logger.Error().
			Err(err).
			Msg("Failed to commit transaction")
		respondWithError(w, http.StatusInternalServerError, "Could not complete the operation")
		return
	}

	logger.Info().
		Int64("viewID", viewID).
		Int64("feedID", feedID).
		Int64("newRefCount", refCount).
		Msg("Feed removed from view successfully")
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (s *Server) handleGetFeed(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	logger := log.With().Str("handler", "getFeed").Logger()
	logger.Debug().Msg("Processing get feed request")

	slug := ps.ByName("slug")
	slug = strings.TrimPrefix(slug, "/")
	slug = strings.TrimSpace(slug)
	if slug == "" {
		logger.Warn().Msg("Invalid slug provided")
		respondWithError(w, http.StatusBadRequest, "Invalid slug")
		return
	}

	view, err := s.queries.GetViewBySlug(r.Context(), slug)
	if err != nil {
		logger.Error().
			Err(err).
			Str("slug", slug).
			Msg("View not found")
		respondWithError(w, http.StatusNotFound, "View not found")
		return
	}

	items, err := s.queries.GetViewFeedsItems(r.Context(), database.GetViewFeedsItemsParams{
		ViewID: view.ID,
		Limit:  30,
	})
	if err != nil {
		logger.Error().
			Err(err).
			Int64("viewID", view.ID).
			Msg("Failed to get feed items")
		respondWithError(w, http.StatusInternalServerError, "Could not get feed items")
		return
	}

	feedURL := fmt.Sprintf("https://%s/feed/%s", r.Host, view.Slug)
	feed := &feeds.Feed{
		Title:       view.Name,
		Link:        &feeds.Link{Href: feedURL},
		Description: "RSS feed for " + view.Name,
		Created:     view.CreatedAt,
	}

	for _, item := range items {
		feed.Items = append(feed.Items, &feeds.Item{
			Title:   item.Title,
			Link:    &feeds.Link{Href: item.Url},
			Id:      item.Url,
			Created: item.AddedAt,
		})
	}

	logger.Debug().
		Int64("viewID", view.ID).
		Str("viewName", view.Name).
		Int("itemCount", len(items)).
		Msg("Feed generated successfully")

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	feed.WriteRss(w)
}

func (s *Server) startFeedUpdater() {
	logger := log.With().Str("component", "feedUpdater").Logger()
	logger.Info().Msg("Starting feed updater")

	logger.Info().Msg("Updating feeds")
	s.updateFeeds()
	logger.Info().Msg("Updated feeds")

	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			logger.Debug().Msg("Running scheduled feed update")
			s.updateFeeds()
		}
	}()
}

func (s *Server) startSessionGC() {
	logger := log.With().Str("component", "sessionGC").Logger()
	logger.Info().Msg("Starting session garbage collector")

	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			logger.Debug().Msg("Running scheduled session cleanup")
			err := s.queries.GCSessions(context.Background())
			if err != nil {
				logger.Error().Err(err).Msg("Error running session GC")
			}
		}
	}()
}

func (s *Server) updateFeeds() {
	logger := log.With().Str("component", "feedUpdater").Logger()
	logger.Debug().Msg("Starting feed update process")

	feeds, err := s.queries.GetFeedsUpdatable(context.Background())
	if err != nil {
		logger.Error().Err(err).Msg("Error getting feeds")
		return
	}

	logger.Debug().Int("feedCount", len(feeds)).Msg("Retrieved feeds to update")

	for _, feed := range feeds {
		feedLogger := logger.With().
			Int64("feedID", feed.ID).
			Str("feedURL", feed.Url).
			Logger()

		parsedFeed, err := s.fp.ParseURL(feed.Url)
		if err != nil {
			feedLogger.Error().Err(err).Msg("Error parsing feed")
			continue
		}

		feedLogger.Debug().
			Int("itemCount", len(parsedFeed.Items)).
			Msg("Retrieved feed items")

		for _, item := range parsedFeed.Items {
			publishedAt := item.PublishedParsed
			if publishedAt == nil {
				t := time.Now()
				publishedAt = &t
			}

			if strings.HasPrefix("/", item.Link) {
				u, err := url.Parse(feed.Url)
				if err != nil {
					feedLogger.Error().
						Err(err).
						Str("itemLink", item.Link).
						Msg("Error parsing feed URL")
					continue
				}
				u.Path = item.Link
				item.Link = u.String()
			}

			err := s.queries.CreateFeedItem(context.Background(), database.CreateFeedItemParams{
				RssFeedID:   feed.ID,
				Title:       item.Title,
				Url:         item.Link,
				PublishedAt: *publishedAt,
			})
			if err != nil {
				if !strings.Contains(err.Error(), "Duplicate entry") {
					feedLogger.Error().
						Err(err).
						Str("itemTitle", item.Title).
						Msg("Error creating feed item")
				} else {
					feedLogger.Debug().
						Str("itemTitle", item.Title).
						Msg("Skipping duplicate feed item")
				}
			} else {
				feedLogger.Debug().
					Str("itemTitle", item.Title).
					Msg("Created new feed item")
			}
		}

		err = s.queries.MarkUpdated(context.Background(), feed.ID)
		if err != nil {
			feedLogger.Error().Err(err).Msg("Error marking feed as updated")
		}
	}
	logger.Info().Msg("Feed update process completed")
}

func main() {
	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	// Pretty print logs to console
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	})

	log.Info().Msg("Starting RSS Aggregator service")

	envloader.LoadEnvFile(".env")

	db, err := sql.Open("mysql", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer db.Close()

	db.SetConnMaxIdleTime(time.Minute * 5)
	db.SetMaxOpenConns(16)

	server := NewServer(db)
	go server.startFeedUpdater()
	go server.startSessionGC()

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	fmt.Println("{\"port\":", ln.Addr().(*net.TCPAddr).Port, "}")

	log.Info().Msgf("Server starting on port %d", ln.Addr().(*net.TCPAddr).Port)
	if err := http.Serve(ln, server.router); err != nil {
		log.Fatal().Err(err).Msg("Server failed to start")
	}
}
