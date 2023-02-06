// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	regoast "github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	regotypes "github.com/open-policy-agent/opa/types"
	"gopkg.in/yaml.v3"
)

const RegoEvaluator = "rego"

type RegoRunner struct {
	benchmark *Benchmark
	resolver  Resolver
}

func NewRegoBenchmarkRunner(resolver Resolver, benchmark *Benchmark) *RegoRunner {
	return &RegoRunner{
		benchmark: benchmark,
		resolver:  resolver,
	}
}

func (rr *RegoRunner) sendEvents(ctx context.Context, stream chan<- *CheckEvent, events ...*CheckEvent) {
	for _, event := range events {
		select {
		case stream <- event:
			log.Tracef("sent event %s", event)
		case <-ctx.Done():
		}
	}
}

func (rr *RegoRunner) RunBenchmark(ctx context.Context, stream chan<- *CheckEvent) {
	for _, rule := range rr.benchmark.Rules {
		resolverOutcome, err := rr.resolver.ResolveInputs(ctx, rule)
		if errors.Is(err, ErrIncompatibleEnvironment) {
			continue
		}
		if err != nil {
			rr.sendEvents(ctx, stream, newCheckError(
				RegoEvaluator, rule, rr.benchmark, resolverOutcome,
				fmt.Errorf("input resolution error for rule=%s: %w", rule.ID, err),
			))
			continue
		}

		log.Infof("running rego check for rule=%s", rule.ID)
		events, err := rr.runRegoCheck(ctx, rule, resolverOutcome)
		if err != nil {
			rr.sendEvents(ctx, stream, newCheckError(
				RegoEvaluator, rule, rr.benchmark, resolverOutcome,
				fmt.Errorf("rego rule check error for rule=%s: %w", rule.ID, err),
			))
			continue
		}

		rr.sendEvents(ctx, stream, events...)
	}
}

func (rr *RegoRunner) RunBenchmarkGatherEvents(ctx context.Context) []*CheckEvent {
	stream := make(chan *CheckEvent)
	go func() {
		rr.RunBenchmark(ctx, stream)
		close(stream)
	}()
	var events []*CheckEvent
	for event := range stream {
		events = append(events, event)
	}
	return events
}

func (rr *RegoRunner) runRegoCheck(ctx context.Context, rule *Rule, resolverOutcome *ResolverOutcome) ([]*CheckEvent, error) {
	log.Tracef("building rego modules for rule=%s", rule.ID)
	modules, err := buildRegoModules(rr.benchmark.dirname, rule)
	if err != nil {
		return nil, fmt.Errorf("could not build rego modules: %w", err)
	}

	regoInput, err := resolverOutcomeToRegoInput(resolverOutcome)
	if err != nil {
		return nil, fmt.Errorf("could not instantiate rego input: %w", err)
	}

	var options []func(*rego.Rego)
	for name, source := range modules {
		options = append(options, rego.Module(name, source))
	}
	options = append(options, regoBuiltins...)
	options = append(options,
		rego.Query("data.datadog.findings"),
		rego.Input(regoInput),
	)

	log.Tracef("starting rego evaluation for rule=%s:%s", rr.benchmark.FrameworkID, rule.ID)
	r := rego.New(options...)
	rSet, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}
	if len(rSet) == 0 || len(rSet[0].Expressions) == 0 {
		return nil, fmt.Errorf("empty results set")
	}

	results, ok := rSet[0].Expressions[0].Value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("could not cast expression value")
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no findings")
	}

	log.TraceFunc(func() string {
		b, _ := json.MarshalIndent(results, "", "\t")
		return fmt.Sprintf("rego evaluation results for %s:%s:\n%s",
			rr.benchmark.FrameworkID, rule.ID, b)
	})
	events := make([]*CheckEvent, 0, len(results))
	for _, data := range results {
		event, err := newCheckEventFromRegoResult(data, rule, resolverOutcome, rr.benchmark)
		if err != nil {
			return nil, fmt.Errorf("could not build event from rego output: %w", err)
		}
		events = append(events, event)
	}

	return events, nil
}

func resolverOutcomeToRegoInput(resolverOutcome *ResolverOutcome) (interface{}, error) {
	// TODO(jinroh): we can avoid this roundtrip by having json markers
	// for all fields of ResolverOutcome. The opa/rego pkg also does
	// a JSON roundtrip for inputs. The only reason to keep it is the
	// simpliciy of the ",inline" marker that does not exist for encoding/json.
	var regoInput struct {
		Context struct {
			RuleID            string      `yaml:"ruleID"`
			Hostname          string      `yaml:"hostname"`
			Input             interface{} `yaml:"input"`
			KubernetesCluster string      `yaml:"kubernetes_cluster,omitempty"`
		} `yaml:"context"`
		Inlined map[string]interface{} `yaml:",inline"`
	}
	regoInput.Context.RuleID = resolverOutcome.RuleID
	regoInput.Context.Hostname = resolverOutcome.Hostname
	regoInput.Context.Input = resolverOutcome.InputSpecs
	regoInput.Context.KubernetesCluster = resolverOutcome.KubernetesCluster
	regoInput.Inlined = resolverOutcome.Resolved
	var v interface{}
	b, err := yaml.Marshal(regoInput)
	if err != nil {
		return nil, err
	}
	log.Tracef("rego input for rule=%s:\n%s", resolverOutcome.RuleID, b)
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func newCheckEventFromRegoResult(data interface{}, rule *Rule, resolverOutcome *ResolverOutcome, benchmark *Benchmark) (*CheckEvent, error) {
	m, ok := data.(map[string]interface{})
	if !ok || m == nil {
		return nil, fmt.Errorf("failed to cast event")
	}
	var result CheckResult
	var err error
	if v, ok := m["status"]; ok {
		status, _ := v.(string)
		switch status {
		case "passed", "pass":
			result = CheckPassed
		case "failing", "fail":
			result = CheckFailed
		case "err", "error":
			var errMsg string
			if data, ok := m["data"].(map[string]interface{}); ok {
				errMsg, _ = data["error"].(string)
			}
			if errMsg == "" {
				errMsg = "unknown"
			}
			err = fmt.Errorf("rego eval error: %s", errMsg)
		default:
			err = fmt.Errorf("rego result invalid: bad status %q", status)
		}
	} else {
		err = fmt.Errorf("rego result invalid: missing status")
	}
	if err != nil {
		return newCheckError(RegoEvaluator, rule, benchmark, resolverOutcome, err), nil
	}
	event := newCheckEvent(RegoEvaluator, rule, benchmark, resolverOutcome, result)
	if v, ok := m["data"]; ok {
		event.Data, _ = v.(map[string]interface{})
	}
	if v, ok := m["resource_id"]; ok {
		event.ResourceID, _ = v.(string)
	}
	if v, ok := m["resource_type"]; ok {
		event.ResourceType, _ = v.(string)
	}
	return event, nil
}

func buildRegoModules(rootDir string, rule *Rule) (map[string]string, error) {
	modules := map[string]string{
		"datadog_helpers.rego": regoHelpersSource,
	}
	ruleFilename := fmt.Sprintf("%s.rego", rule.ID)
	ruleCode, err := loadFile(rootDir, ruleFilename)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(ruleCode) > 0 {
		modules[ruleFilename] = string(ruleCode)
	}
	for _, name := range rule.Imports {
		if _, ok := modules[name]; ok {
			continue
		}
		source, err := loadFile(rootDir, name)
		if err != nil {
			return nil, err
		}
		modules[name] = string(source)
	}
	return modules, nil
}

const regoHelpersSource = `package datadog

raw_finding(status, resource_type, resource_id, event_data) = f {
	f := {
		"status": status,
		"resource_type": resource_type,
		"resource_id": resource_id,
		"data": event_data,
	}
}

passed_finding(resource_type, resource_id, event_data) = f {
	f := raw_finding("passed", resource_type, resource_id, event_data)
}

failing_finding(resource_type, resource_id, event_data) = f {
	f := raw_finding("failing", resource_type, resource_id, event_data)
}

error_finding(resource_type, resource_id, error_msg) = f {
	f := raw_finding("error", resource_type, resource_id, {
		"error": error_msg
	})
}
`

var regoBuiltins = []func(*rego.Rego){
	rego.Function1(
		&rego.Function{
			Name: "parse_octal",
			Decl: regotypes.NewFunction(regotypes.Args(regotypes.S), regotypes.N),
		},
		func(_ rego.BuiltinContext, a *regoast.Term) (*regoast.Term, error) {
			str, ok := a.Value.(regoast.String)
			if !ok {
				return nil, fmt.Errorf("rego builtin parse_octal was not given a String")
			}
			value, err := strconv.ParseInt(string(str), 8, 0)
			if err != nil {
				return nil, fmt.Errorf("rego builtin parse_octal failed to parse into int: %w", err)
			}
			return regoast.IntNumberTerm(int(value)), err
		},
	),
}
