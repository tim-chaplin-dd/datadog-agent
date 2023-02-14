// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows && kubeapiserver
// +build !windows,kubeapiserver

package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"k8s.io/client-go/dynamic"

	"github.com/DataDog/datadog-agent/cmd/security-agent/command"
	"github.com/DataDog/datadog-agent/cmd/security-agent/flags"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/pkg/compliance"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/hostname"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"
	"github.com/DataDog/datadog-agent/pkg/util/startstop"
)

// CliParams needs to be exported because the compliance subcommand is tightly coupled to this subcommand and tests need to be able to access this type.
type CliParams struct {
	*command.GlobalParams

	args []string

	framework         string
	file              string
	verbose           bool
	report            bool
	overrideRegoInput string
	dumpRegoInput     string
	dumpReports       string
	skipRegoEval      bool
}

func SecurityAgentCommands(globalParams *command.GlobalParams) []*cobra.Command {
	return commandsWrapped(func() core.BundleParams {
		return core.BundleParams{
			ConfigParams: config.NewSecurityAgentParams(globalParams.ConfigFilePaths),
			LogParams:    log.LogForOneShot(command.LoggerName, "info", true),
		}
	})
}

func ClusterAgentCommands(bundleParams core.BundleParams) []*cobra.Command {
	return commandsWrapped(func() core.BundleParams {
		return bundleParams
	})
}

func commandsWrapped(bundleParamsFactory func() core.BundleParams) []*cobra.Command {
	checkArgs := &CliParams{}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Run compliance check(s)",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			checkArgs.args = args

			bundleParams := bundleParamsFactory()
			if checkArgs.verbose {
				bundleParams.LogParams = log.LogForOneShot(bundleParams.LogParams.LoggerName(), "trace", true)
			}

			return fxutil.OneShot(RunCheck,
				fx.Supply(checkArgs),
				fx.Supply(bundleParams),
				core.Bundle,
			)
		},
	}

	cmd.Flags().StringVarP(&checkArgs.framework, flags.Framework, "", "", "Framework to run the checks from")
	cmd.Flags().StringVarP(&checkArgs.file, flags.File, "f", "", "Compliance suite file to read rules from")
	cmd.Flags().BoolVarP(&checkArgs.verbose, flags.Verbose, "v", false, "Include verbose details")
	cmd.Flags().BoolVarP(&checkArgs.report, flags.Report, "r", false, "Send report")
	cmd.Flags().StringVarP(&checkArgs.overrideRegoInput, flags.OverrideRegoInput, "", "", "Rego input to use when running rego checks")
	cmd.Flags().StringVarP(&checkArgs.dumpReports, flags.DumpReports, "", "", "Path to file where to dump reports")

	return []*cobra.Command{cmd}
}

func RunCheck(log log.Component, config config.Component, checkArgs *CliParams) error {
	if checkArgs.skipRegoEval && checkArgs.dumpReports != "" {
		return errors.New("skipping the rego evaluation does not allow the generation of reports")
	}

	hname, err := hostname.Get(context.TODO())
	if err != nil {
		return err
	}

	var resolver compliance.Resolver
	if checkArgs.overrideRegoInput != "" {
		resolver = &fakeResolver{}
	} else if flavor.GetFlavor() == flavor.ClusterAgent {
		resolver = compliance.NewResolver(compliance.ResolverOptions{
			Hostname:           hname,
			DockerProvider:     compliance.DefaultDockerProvider,
			LinuxAuditProvider: compliance.DefaultLinuxAuditProvider,
			KubernetesProvider: complianceKubernetesProvider,
		})
	} else {
		fmt.Println("coucou")
		resolver = compliance.NewResolver(compliance.ResolverOptions{
			Hostname:           hname,
			HostRoot:           os.Getenv("HOST_ROOT"),
			DockerProvider:     compliance.DefaultDockerProvider,
			LinuxAuditProvider: compliance.DefaultLinuxAuditProvider,
		})
	}
	defer resolver.Close()

	configDir := config.GetString("compliance_config.dir")
	var benchmarks []*compliance.Benchmark
	if checkArgs.file != "" {
		benchmarks, err = compliance.LoadBenchmarkFiles(filepath.Dir(checkArgs.file), filepath.Base(checkArgs.file))
		if err != nil {
			log.Errorf("Could not load benchmark file %q: %s", checkArgs.file, err)
			return err
		}
	} else if checkArgs.framework != "" {
		benchmarks, err = compliance.LoadBenchmarkFiles(configDir, checkArgs.framework+".yaml")
		if err != nil {
			log.Errorf("Could not load benchmark file %q: %s", checkArgs.file, err)
			return err
		}
	} else {
		benchmarks, err = compliance.LoadBenchmarkFiles(configDir, compliance.ListBenchmarksFiles(configDir)...)
		if err != nil {
			log.Errorf("Could not load benchmark file %q: %s", checkArgs.file, err)
			return err
		}
	}

	// options = append(options, checks.WithRegoEvalSkip(checkArgs.skipRegoEval))
	// options = append(options, checks.WithRegoInputDumpPath(checkArgs.dumpRegoInput))

	if len(checkArgs.args) != 0 {
		benchmarks = filterBencharmarksRule(benchmarks, checkArgs.args[0])
	}
	if len(benchmarks) == 0 {
		log.Errorf("")
		return fmt.Errorf("no benchmarks to run")
	}

	for _, benchmark := range benchmarks {
		runner := compliance.NewRegoBenchmarkRunner(resolver, benchmark)
		events := runner.RunBenchmarkGatherEvents(context.Background())
		if checkArgs.dumpReports != "" {
			if err := dumpComplianceEvents(checkArgs.dumpReports, events); err != nil {
				log.Error(err)
				return err
			}
		}
		if checkArgs.report {
			if err := reportComplianceEvents(log, config, events); err != nil {
				log.Error(err)
				return err
			}
		}
	}
	return nil
}

func dumpComplianceEvents(reportFile string, events []*compliance.CheckEvent) error {
	eventsMap := make(map[string][]*compliance.CheckEvent)
	for _, event := range events {
		eventsMap[event.RuleID] = append(eventsMap[event.RuleID], event)
	}
	b, err := json.MarshalIndent(eventsMap, "", "\t")
	if err != nil {
		return fmt.Errorf("could not marshal events map: %w", err)
	}
	if err := os.WriteFile(reportFile, b, 0644); err != nil {
		return fmt.Errorf("could not write report file in %q: %w", reportFile, err)
	}
	return nil
}

func reportComplianceEvents(log log.Component, config config.Component, events []*compliance.CheckEvent) error {
	stopper := startstop.NewSerialStopper()
	defer stopper.Stop()
	runPath := config.GetString("compliance_config.run_path")
	endpoints, context, err := command.NewLogContextCompliance(log)
	if err != nil {
		return fmt.Errorf("reporter: could not reate log context for compliance: %w", err)
	}
	reporter, err := compliance.NewLogReporter(stopper, "compliance-agent", "compliance", runPath, endpoints, context)
	if err != nil {
		return fmt.Errorf("reporter: could not create: %w", err)
	}
	for _, event := range events {
		buf, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("reporter: could not marshal event: %w", err)
		}
		reporter.ReportRaw(buf, "")
	}
	return nil
}

func complianceKubernetesProvider(_ctx context.Context) (dynamic.Interface, error) {
	ctx, cancel := context.WithTimeout(_ctx, 2*time.Second)
	defer cancel()
	apiCl, err := apiserver.WaitForAPIClient(ctx)
	if err != nil {
		return nil, err
	}
	return apiCl.DynamicCl, nil
}

func filterBencharmarksRule(benchmarks []*compliance.Benchmark, ruleID string) []*compliance.Benchmark {
	var filteredBenchmarks []*compliance.Benchmark
	for _, benchmark := range benchmarks {
		var filteredRules []*compliance.Rule
		for _, rule := range benchmark.Rules {
			if rule.ID == ruleID {
				filteredRules = append(filteredRules, rule)
			}
		}
		if len(filteredRules) > 0 {
			benchmark.Rules = filteredRules
			filteredBenchmarks = append(filteredBenchmarks, benchmark)
		}
	}
	return filteredBenchmarks
}

type fakeResolver struct {
	output *compliance.ResolverOutcome
}

func (r *fakeResolver) ResolveInputs(ctx context.Context, rule *compliance.Rule) (*compliance.ResolverOutcome, error) {
	return r.output, nil
}

func (r *fakeResolver) Close() error {
	return nil
}
