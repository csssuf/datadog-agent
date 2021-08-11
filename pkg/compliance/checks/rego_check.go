// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/open-policy-agent/opa/rego"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	"github.com/DataDog/datadog-agent/pkg/compliance"
	"github.com/DataDog/datadog-agent/pkg/compliance/checks/env"
)

type regoCheck struct {
	env.Env

	ruleID      string
	description string
	interval    time.Duration

	suiteMeta *compliance.SuiteMeta

	scope           compliance.RuleScope
	resourceHandler resourceReporter

	resources         []compliance.RegoResource
	preparedEvalQuery rego.PreparedEvalQuery

	eventNotify eventNotify
}

func (r *regoCheck) compileQuery(module, query string) error {
	ctx := context.TODO()

	preparedEvalQuery, err := rego.New(
		rego.Query("result = "+query),
		rego.Module(fmt.Sprintf("rule_%s.rego", r.ruleID), module),
	).PrepareForEval(ctx)

	if err != nil {
		return err
	}

	r.preparedEvalQuery = preparedEvalQuery

	return nil
}

func (r *regoCheck) Stop() {
}

func (r *regoCheck) Cancel() {
}

func (r *regoCheck) String() string {
	return compliance.CheckName(r.ruleID, r.description)
}

func (r *regoCheck) Configure(config, initConfig integration.Data, source string) error {
	return nil
}

func (r *regoCheck) Interval() time.Duration {
	return r.interval
}

func (r *regoCheck) ID() check.ID {
	return check.ID(r.ruleID)
}

func (r *regoCheck) GetWarnings() []error {
	return nil
}

func (r *regoCheck) GetSenderStats() (check.SenderStats, error) {
	return check.NewSenderStats(), nil
}

func (r *regoCheck) Version() string {
	return r.suiteMeta.Version
}

func (r *regoCheck) ConfigSource() string {
	return r.suiteMeta.Source
}

func (r *regoCheck) IsTelemetryEnabled() bool {
	return false
}

func (r *regoCheck) Run() error {
	if !r.IsLeader() {
		return nil
	}

	var err error

	fmt.Printf("Hey I'm executed\n")

	input := make(map[string][]interface{})

	for _, resource := range r.resources {
		resolve, _, err := resourceKindToResolverAndFields(r.Env, r.ruleID, resource.Kind())
		if err != nil {
			return fmt.Errorf("%s: failed to find resource resolver for resource kind: %s", r.ruleID, resource.Kind())
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)

		resolved, err := resolve(ctx, r.Env, r.ruleID, resource.BaseResource)
		if err != nil {
			cancel()
			return err
		}
		cancel()

		switch instance := resolved.(type) {
		case resolvedInstance:
			vars, exists := input[string(resource.Kind())]
			if !exists {
				vars = []interface{}{}
			}
			input[string(resource.Kind())+"s"] = append(vars, instance.Vars().GoMap())
		}

		/*e := &event.Event{
			AgentRuleID:      r.ruleID,
			AgentFrameworkID: r.suiteMeta.Framework,
			ResourceID:       resource.ID,
			ResourceType:     resource.Type,
			Result:           result,
			Data:             data,
		}

		log.Debugf("%s: reporting [%s] [%s] [%s]", c.ruleID, e.Result, e.ResourceID, e.ResourceType)

		c.Reporter().Report(e)
		if c.eventNotify != nil {
			c.eventNotify(c.ruleID, e)
		}*/
	}

	data, err := json.Marshal(input)
	if err != nil {
		return err
	}

	ctx := context.TODO()
	results, err := r.preparedEvalQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return err
	} else if len(results) == 0 {
		return nil
	}

	result, ok := results[0].Bindings["result"].(bool)
	if !ok {
		return errors.New("wrong result type")
	}

	if 

	fmt.Printf("ZZZ: %+v %+v, :%+v, %s\n", spew.Sdump(input), results, err, string(data))

	return err
}
