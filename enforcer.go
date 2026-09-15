
package auth

import (
	"embed"
	"fmt"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

//go:embed model/rbac_model.conf
var modelFS embed.FS

type Enforcer struct {
	enforcer *casbin.Enforcer
	mu       sync.RWMutex
}

func NewEnforcer(
	dsn string,
) (*Enforcer, error) {

	// Koneksi database
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

	// Buat tabel Casbin jika belum ada
	adapter, err := gormadapter.NewAdapterByDB(
		db,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"create casbin adapter: %w",
			err,
		)
	}

	// Load model dari embed
	modelBytes, err := modelFS.ReadFile(
		"model.conf",
	)

	if err != nil {
		return nil, fmt.Errorf(
			"read casbin model: %w",
			err,
		)
	}

	m, err := model.NewModelFromString(
		string(modelBytes),
	)

	if err != nil {
		return nil, fmt.Errorf(
			"load casbin model: %w",
			err,
		)
	}

	// Buat Enforcer
	e, err := casbin.NewEnforcer(
		m,
		adapter,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"create enforcer: %w",
			err,
		)
	}

	return &Enforcer{
		enforcer: e,
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