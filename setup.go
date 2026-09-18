package authz

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/redis/go-redis/v9"
)

func SetupAuthorization(
	ctx context.Context,
	db *gorm.DB,
	redisClient *redis.Client,
) (*Middleware, error) {
	
	enforcer, err := NewEnforcer(
		db.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("create casbin enforcer: %w", err)
	}

	if err := enforcer.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("load casbin policy: %w", err)
	}

	StartReloadListener(
		ctx,
		redisClient,
		enforcer,
	)

	return NewMiddleware(enforcer), nil
}