package auth

import (
	"embed"
	"fmt"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

//go:embed model.conf
var modelFS embed.FS

type Enforcer struct {
	enforcer *casbin.Enforcer
	mu       sync.RWMutex
}

func NewEnforcer(
	dsn string,
) (*Enforcer, error) {

	db, err := gorm.Open(
		mysql.Open(dsn),
		&gorm.Config{},
	)

	if err != nil {
		return nil, fmt.Errorf(
			"connect database: %w",
			err,
		)
	}

	adapter := NewDatabaseAdapter(db)

	modelBytes, err := modelFS.ReadFile("model.conf",)

	if err != nil {
		return nil, fmt.Errorf(
		"read casbin model: %w",
		err,
	)
	}

	casbinModel, err := model.NewModelFromString(
		string(modelBytes),
	)

	if err != nil {
		return nil, fmt.Errorf(
			"create casbin model: %w",
			err,
		)
	}

	enforcer, err := casbin.NewEnforcer(
		casbinModel,
		adapter,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"create casbin enforcer: %w",
			err,
		)
	}

	return &Enforcer{
		enforcer: enforcer,
	}, nil
}

func (e *Enforcer) LoadPolicy() error {

	e.mu.Lock()
	defer e.mu.Unlock()

	return e.enforcer.LoadPolicy()
}

func (e *Enforcer) Enforce(
	subject string,
	guard string,
	object string,
	action string,
) (bool, error) {

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.enforcer.Enforce(
		subject,
		guard,
		object,
		action,
	)
}