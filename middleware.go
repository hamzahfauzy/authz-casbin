package auth

import (
	"net/http"
	"github.com/gin-gonic/gin"
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
		user_id, ok := c.Get("user_id")

		if !ok {
			pkgResponse.UnauthorizedError(
				c,
				"authentication required",
			)
			c.Abort()
			return
		}

		// Get actor type / guard
		actorTypeValue, exists := c.Get("actor_type")

		if !exists {
			pkgResponse.UnauthorizedError(
				c,
				"authentication context missing",
			)
			c.Abort()
			return
		}

		guard, ok := actorTypeValue.(string)

		if !ok || guard == "" {
			pkgResponse.UnauthorizedError(
				c,
				"authentication context invalid",
			)
			c.Abort()
			return
		}

		userId, good := user_id.(string)

		if !good || userId == "" {
			pkgResponse.UnauthorizedError(
				c,
				"authentication context invalid",
			)
			c.Abort()
			return
		}

		// Check permission using Casbin
		allowed, err := m.enforcer.Enforce(
			userId,
			guard,
			object,
			action,
		)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "authorization error",
				"error":   err.Error(),
				"data": gin.H{ "userId": userId, "guard": guard, "object": object, "action": action, },
			})
			c.Abort()
			return
		}

		// Permission denied
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"message": "permission denied",
				"data": gin.H{ "userId": userId, "guard": guard, "object": object, "action": action, },
			})
			c.Abort()
			return
		}

		c.Next()
	}
}