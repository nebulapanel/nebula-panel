package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/nebula-panel/nebula/apps/api/internal/models"
	"github.com/nebula-panel/nebula/apps/api/internal/store"
)

type ctxKey string

const sessionKey ctxKey = "session"

func WithSession(ctx context.Context, s models.Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

func SessionFromContext(ctx context.Context) (models.Session, bool) {
	s, ok := ctx.Value(sessionKey).(models.Session)
	return s, ok
}

func RequireSession(st *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" {
				token = r.Header.Get("X-Session-Token")
			}
			sess, ok := st.ValidateSession(strings.TrimSpace(token))
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithSession(r.Context(), sess)))
		})
	}
}
