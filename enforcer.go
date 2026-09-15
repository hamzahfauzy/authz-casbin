package auth

import (
	"embed"
	"fmt"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	// "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

//go:embed model.conf
var modelFS embed.FS

type Enforcer struct {
	enforcer *casbin.Enforcer
	mu       sync.RWMutex
}

func NewEnforcer(
	db *gorm.DB,
) (*Enforcer, error) {

	adapter := NewDatabaseAdapter(db)

	modelBytes, err := modelFS.ReadFile("model.conf",)

	if err != nil {
		return nil, fmt.Errorf(
		"read casbin model: %w",
		err,
	)
	}

	fmt.Println("casbin model read success")

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

func (e *Enforcer) GetPolicy() ([][]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.enforcer.GetPolicy()
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