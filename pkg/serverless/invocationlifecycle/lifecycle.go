// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package invocationlifecycle

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	serverlessLog "github.com/DataDog/datadog-agent/pkg/serverless/logs"
	serverlessMetrics "github.com/DataDog/datadog-agent/pkg/serverless/metrics"
	"github.com/DataDog/datadog-agent/pkg/serverless/trace/inferredspan"
	"github.com/DataDog/datadog-agent/pkg/serverless/trigger"
	"github.com/DataDog/datadog-agent/pkg/trace/api"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type RequestHandler struct {
	executionContext *ExecutionStartInfo
}

func (r *RequestHandler) GetExecutionContext() *ExecutionStartInfo {
	return r.executionContext
}

// LifecycleProcessor is a InvocationProcessor implementation
type LifecycleProcessor struct {
	ExtraTags            *serverlessLog.Tags
	ProcessTrace         func(p *api.Payload)
	Demux                aggregator.Demultiplexer
	DetectLambdaLibrary  func() bool
	InferredSpansEnabled bool

	requestHandler *RequestHandler
}

// GetExecutionContext implements InvocationProcessor
func (lp *LifecycleProcessor) GetExecutionContext() *ExecutionStartInfo {
	return lp.requestHandler.executionContext
}

var inferredSpan inferredspan.InferredSpan

// OnInvokeStart is the hook triggered when an invocation has started
func (lp *LifecycleProcessor) OnInvokeStart(startDetails *InvocationStartDetails) {
	log.Debug("[lifecycle] onInvokeStart ------")
	log.Debugf("[lifecycle] Invocation has started at: %v", startDetails.StartTime)
	log.Debugf("[lifecycle] Invocation invokeEvent payload is: %s", startDetails.InvokeEventRawPayload)
	log.Debug("[lifecycle] ---------------------------------------")

	parsedPayload, err := trigger.Unmarshal(startDetails.InvokeEventRawPayload)
	if err != nil {
		log.Debugf("[lifecycle] Failed to parse event payload")
		return
	}

	// Singleton instance of request handler
	if lp.requestHandler == nil {
		lp.requestHandler = &RequestHandler{}
	}

	lp.requestHandler.executionContext = &ExecutionStartInfo{
		startTime: time.Now(),
	}

	if !lp.DetectLambdaLibrary() {
		if lp.InferredSpansEnabled {
			log.Debug("[lifecycle] Attempting to create inferred span")
			inferredSpan.GenerateInferredSpan(startDetails.StartTime)
			inferredSpan.DispatchInferredSpan(parsedPayload)
		}

		startExecutionSpan(lp.requestHandler.executionContext, startDetails.StartTime, startDetails.InvokeEventRawPayload, startDetails.InvokeEventHeaders, lp.InferredSpansEnabled)
	}
}

// OnInvokeEnd is the hook triggered when an invocation has ended
func (lp *LifecycleProcessor) OnInvokeEnd(endDetails *InvocationEndDetails) {
	log.Debug("[lifecycle] onInvokeEnd ------")
	log.Debugf("[lifecycle] Invocation has finished at: %v", endDetails.EndTime)
	log.Debugf("[lifecycle] Invocation isError is: %v", endDetails.IsError)
	log.Debug("[lifecycle] ---------------------------------------")

	if !lp.DetectLambdaLibrary() {
		log.Debug("Creating and sending function execution span for invocation")
		endExecutionSpan(lp.requestHandler.executionContext, lp.ProcessTrace, endDetails.RequestID, endDetails.EndTime, endDetails.IsError, endDetails.ResponseRawPayload)

		if lp.InferredSpansEnabled {
			log.Debug("[lifecycle] Attempting to complete the inferred span")
			if inferredSpan.Span.Start != 0 {
				inferredSpan.CompleteInferredSpan(lp.ProcessTrace, endDetails.EndTime, endDetails.IsError, lp.requestHandler.executionContext.TraceID, lp.requestHandler.executionContext.SamplingPriority)
				log.Debugf("[lifecycle] The inferred span attributes are: %v", inferredSpan)
			} else {
				log.Debug("[lifecyle] Failed to complete inferred span due to a missing start time. Please check that the event payload was received with the appropriate data")
			}
		}
	}

	if endDetails.IsError {
		serverlessMetrics.SendErrorsEnhancedMetric(
			lp.ExtraTags.Tags, endDetails.EndTime, lp.Demux,
		)
	}
}
