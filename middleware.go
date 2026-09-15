package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turahe/pkg/jwt"
	pkgResponse "github.com/turahe/pkg/response"
)

type Middleware struct {
	enforcer *Enforcer
}

func NewMiddleware(enforcer *Enforcer) *Middleware {
	return &Middleware{
		enforcer: enforcer,
	}
}

func (m *Middleware) Require(
	object string,
	action string,
) gin.HandlerFunc {

	return func(c *gin.Context) {

		userUUID, ok := jwt.GetCurrentUserUUID(c)

		if !ok {
			pkgResponse.UnauthorizedError(c, "authentication required")
			c.Abort()
			return
		}

		guard := c.Get("actor_type")

		if guard == "" {
			pkgResponse.UnauthorizedError(c, "authentication context missing")
			c.Abort()
			return
		}

		allowed, err := m.enforcer.Enforce(
			userUUID,
			guard,
			object,
			action,
		)

		if err != nil {
			pkgResponse.UnauthorizedError(c, "authorization error")
			c.Abort()
			return
		}

		if !allowed {
			pkgResponse.UnauthorizedError(c, "permission denied")
			c.Abort()
			return
		}

		c.Next()
	}
}