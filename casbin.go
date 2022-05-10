package main

import (
	"os"
	"path/filepath"

	"github.com/casbin/casbin/v2"
	jsonadapter "github.com/casbin/json-adapter/v2"
)

type CasbinEnforcer struct {
	enforcer *casbin.Enforcer
	data     []byte
}

func NewEnforcer() (*CasbinEnforcer, error) {
	casbinModelFile := filepath.Join(CONF_DIR, "model.conf")
	policyDefinitionFile := filepath.Join(CONF_DIR, "policy.json")

	data, err := os.ReadFile(policyDefinitionFile)
	if err != nil {
		return nil, err
	}

	adapter := jsonadapter.NewAdapter(&data)

	enforcer, err := casbin.NewEnforcer(casbinModelFile, adapter)
	if err != nil {
		return nil, err
	}

	enforcer.LoadPolicy()

	return &CasbinEnforcer{
		enforcer: enforcer,
		data:     data,
	}, nil
}

func (c *CasbinEnforcer) AddGroupingPolicies(policies []GroupingPolicy) error {
	var rules [][]string
	for _, p := range policies {
		rules = append(rules, []string{p.Subject, p.Role, p.Domain})
	}

	_, err := c.enforcer.AddGroupingPolicies(rules)
	if err != nil {
		return err
	}

	c.enforcer.SavePolicy()

	return nil
}

func (c *CasbinEnforcer) IsAuthorized(req AuthorizationRequest) (bool, error) {
	return c.enforcer.Enforce(req.Subject, req.Domain, req.Object, req.Action)
}
