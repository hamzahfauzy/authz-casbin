package auth

import (
	"fmt"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"gorm.io/gorm"
)

type CasbinRule struct {
	ID    uint   `gorm:"column:id"`
	Ptype string `gorm:"column:ptype"`
	V0    string `gorm:"column:v0"`
	V1    string `gorm:"column:v1"`
	V2    string `gorm:"column:v2"`
	V3    string `gorm:"column:v3"`
	V4    string `gorm:"column:v4"`
	V5    string `gorm:"column:v5"`
}

func (CasbinRule) TableName() string {
	return "casbin_rule"
}

type DatabaseAdapter struct {
	db *gorm.DB
}

func NewDatabaseAdapter(db *gorm.DB) *DatabaseAdapter {
	return &DatabaseAdapter{
		db: db,
	}
}

// LoadPolicy membaca policy dari VIEW casbin_rule.
func (a *DatabaseAdapter) LoadPolicy(
	model model.Model,
) error {

	var rules []CasbinRule

	err := a.db.
		Table("casbin_rule").
		Order("id ASC").
		Find(&rules).
		Error

	if err != nil {
		return fmt.Errorf(
			"load casbin policy: %w",
			err,
		)
	}

	fmt.Println("casbin policy loaded")

	for _, rule := range rules {

		line := rule.Ptype

		values := []string{
			rule.V0,
			rule.V1,
			rule.V2,
			rule.V3,
			rule.V4,
			rule.V5,
		}

		for _, value := range values {

			if value == "" {
				break
			}

			line += ", " + value
		}

		persist.LoadPolicyLine(
			line,
			model,
		)
	}

	return nil
}

// SavePolicy tidak didukung karena casbin_rule adalah VIEW.
func (a *DatabaseAdapter) SavePolicy(
	model model.Model,
) error {

	return fmt.Errorf(
		"casbin policy is read-only",
	)
}

// AddPolicy tidak didukung.
func (a *DatabaseAdapter) AddPolicy(
	sec string,
	ptype string,
	rule []string,
) error {

	return fmt.Errorf(
		"casbin policy is read-only",
	)
}

// RemovePolicy tidak didukung.
func (a *DatabaseAdapter) RemovePolicy(
	sec string,
	ptype string,
	rule []string,
) error {

	return fmt.Errorf(
		"casbin policy is read-only",
	)
}

// RemoveFilteredPolicy tidak didukung.
func (a *DatabaseAdapter) RemoveFilteredPolicy(
	sec string,
	ptype string,
	fieldIndex int,
	fieldValues ...string,
) error {

	return fmt.Errorf(
		"casbin policy is read-only",
	)
}