// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package resolvers

import (
	"context"

	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-agent/pkg/tagger/collectors"
	"github.com/DataDog/datadog-agent/pkg/tagger/remote"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// ContainerResolver is used to resolve the container context of the events
type ContainerResolver struct {
	tagger Tagger
}

// GetContainerID returns the container id of the given pid
func (cr *ContainerResolver) GetContainerID(pid uint32) (utils.ContainerID, error) {
	// Parse /proc/[pid]/task/[pid]/cgroup
	return utils.GetProcContainerID(pid, pid)
}

type Tagger interface {
	Init(context.Context) error
	Stop() error
	Tag(entity string, cardinality collectors.TagCardinality) ([]string, error)
}

type nullTagger struct{}

func (n *nullTagger) Init(context.Context) error {
	return nil
}

func (n *nullTagger) Stop() error {
	return nil
}

func (n *nullTagger) Tag(entity string, cardinality collectors.TagCardinality) ([]string, error) {
	return nil, nil
}

// Start the resolver
func (t *ContainerResolver) Start(ctx context.Context) error {
	go func() {
		if err := t.tagger.Init(ctx); err != nil {
			log.Errorf("failed to init tagger: %s", err)
		}
	}()

	go func() {
		<-ctx.Done()
		_ = t.tagger.Stop()
	}()

	return nil
}

// Resolve returns the tags for the given id
func (t *ContainerResolver) Resolve(id string) []string {
	tags, _ := t.tagger.Tag("container_id://"+id, collectors.OrchestratorCardinality)
	return tags
}

// ResolveWithErr returns the tags for the given id
func (t *ContainerResolver) ResolveWithErr(id string) ([]string, error) {
	return t.tagger.Tag("container_id://"+id, collectors.OrchestratorCardinality)
}

// GetValue return the tag value for the given id and tag name
func (t *ContainerResolver) GetValue(id string, tag string) string {
	return utils.GetTagValue(tag, t.Resolve(id))
}

// Stop the resolver
func (t *ContainerResolver) Stop() error {
	return t.tagger.Stop()
}

// NewContainerResolver returns a new tags resolver
func NewContainerResolver(config *config.Config) *ContainerResolver {
	if config.RemoteTaggerEnabled {
		options, err := remote.NodeAgentOptions()
		if err != nil {
			log.Errorf("unable to configure the remote tagger: %s", err)
		} else {
			return &ContainerResolver{
				tagger: remote.NewTagger(options),
			}
		}
	}

	return &ContainerResolver{
		tagger: &nullTagger{},
	}
}
