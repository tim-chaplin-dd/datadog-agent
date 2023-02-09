// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package report

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/DataDog/datadog-agent/pkg/aggregator/mocksender"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/snmp/internal/checkconfig"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/snmp/internal/valuestore"
)

func Test_metricSender_sendBandwidthUsageMetric(t *testing.T) {
	type Metric struct {
		name  string
		value float64
	}
	tests := []struct {
		name             string
		symbol           checkconfig.SymbolConfig
		fullIndex        string
		values           *valuestore.ResultValueStore
		tags             []string
		interfaceConfigs *checkconfig.InterfaceConfig
		expectedMetric   []Metric
		expectedError    error
	}{
		{
			name:      "snmp.ifBandwidthInUsage.Rate submitted",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			fullIndex: "9",
			tags:      []string{"abc"},
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: 80.0,
						},
					},
				},
			},
			expectedMetric: []Metric{
				// ((5000000 * 8) / (80 * 1000000)) * 100 = 50.0
				{"snmp.ifBandwidthInUsage.rate", 50.0},
			},
		},
		{
			name:      "snmp.ifBandwidthOutUsage.Rate submitted",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.10", Name: "ifHCOutOctets"},
			fullIndex: "9",
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: 80.0,
						},
					},
				},
			},
			expectedMetric: []Metric{
				// ((1000000 * 8) / (80 * 1000000)) * 100 = 10.0
				{"snmp.ifBandwidthOutUsage.rate", 10.0},
			},
		},
		{
			name:      "not a bandwidth metric",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.99", Name: "notABandwidthMetric"},
			fullIndex: "9",
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{},
			},
			expectedMetric: []Metric{},
		},
		{
			name:      "missing ifHighSpeed",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			fullIndex: "9",
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
				},
			},
			expectedMetric: []Metric{},
			expectedError:  fmt.Errorf("bandwidth usage: missing `ifHighSpeed` metric, skipping metric. fullIndex=9"),
		},
		{
			name:      "missing ifHCInOctets",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			fullIndex: "9",
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: 80.0,
						},
					},
				},
			},
			expectedMetric: []Metric{},
			expectedError:  fmt.Errorf("bandwidth usage: missing `ifHCInOctets` metric, skipping this row. fullIndex=9"),
		},
		{
			name:      "missing ifHCOutOctets",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCOutOctets"},
			fullIndex: "9",
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: 80.0,
						},
					},
				},
			},
			expectedMetric: []Metric{},
			expectedError:  fmt.Errorf("bandwidth usage: missing `ifHCOutOctets` metric, skipping this row. fullIndex=9"),
		},
		{
			name:      "missing ifHCInOctets value",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			fullIndex: "9",
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9999": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: 80.0,
						},
					},
				},
			},
			expectedMetric: []Metric{},
			expectedError:  fmt.Errorf("bandwidth usage: missing value for `ifHCInOctets` metric, skipping this row. fullIndex=9"),
		},
		{
			name:      "missing ifHighSpeed value",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			fullIndex: "9",
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"999": {
							Value: 80.0,
						},
					},
				},
			},
			expectedMetric: []Metric{},
			expectedError:  fmt.Errorf("bandwidth usage: missing value for `ifHighSpeed`, skipping this row. fullIndex=9"),
		},
		{
			name:      "cannot convert ifHighSpeed to float",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			fullIndex: "9",
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: "abc",
						},
					},
				},
			},
			expectedMetric: []Metric{},
			expectedError:  fmt.Errorf("failed to convert ifHighSpeedValue to float64: failed to parse `abc`: strconv.ParseFloat: parsing \"abc\": invalid syntax"),
		},
		{
			name:      "cannot convert ifHCInOctets to float",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			fullIndex: "9",
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: "abc",
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: 80.0,
						},
					},
				},
			},
			expectedMetric: []Metric{},
			expectedError:  fmt.Errorf("failed to convert octetsValue to float64: failed to parse `abc`: strconv.ParseFloat: parsing \"abc\": invalid syntax"),
		},
		{
			name:      "[custom speed] snmp.ifBandwidthInUsage.rate with custom interface speed matched by name",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			fullIndex: "9",
			interfaceConfigs: &checkconfig.InterfaceConfig{
				Name:    "eth0",
				InSpeed: 160_000_000,
			},
			tags: []string{
				"interface:eth0",
			},
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: 80.0,
						},
					},
				},
			},
			expectedMetric: []Metric{
				// ((5000000 * 8) / (160 * 1000000)) * 100 = 25.0
				{"snmp.ifBandwidthInUsage.rate", 25.0},
			},
		},
		{
			name:      "[custom speed] snmp.ifBandwidthInUsage.rate with custom interface speed matched by index",
			symbol:    checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			fullIndex: "9",
			interfaceConfigs: &checkconfig.InterfaceConfig{
				Index:   9,
				InSpeed: 160_000_000,
			},
			tags: []string{
				"interface:eth0",
			},
			values: &valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: 80.0,
						},
					},
				},
			},
			expectedMetric: []Metric{
				// ((5000000 * 8) / (160 * 1000000)) * 100 = 25.0
				{"snmp.ifBandwidthInUsage.rate", 25.0},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := mocksender.NewMockSender("testID") // required to initiate aggregator
			sender.On("Rate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

			ms := &MetricSender{
				sender: sender,
			}
			err := ms.sendBandwidthUsageMetric(tt.symbol, tt.fullIndex, tt.values, tt.tags, tt.interfaceConfigs)
			assert.Equal(t, tt.expectedError, err)

			for _, metric := range tt.expectedMetric {
				sender.AssertMetric(t, "Rate", metric.name, metric.value, "", tt.tags)
			}
		})
	}
}
func Test_metricSender_trySendBandwidthUsageMetric(t *testing.T) {
	type Metric struct {
		name  string
		value float64
	}
	tests := []struct {
		name           string
		symbol         checkconfig.SymbolConfig
		fullIndex      string
		values         *valuestore.ResultValueStore
		expectedMetric []Metric
	}{
		{
			"snmp.ifBandwidthInUsage.Rate submitted",
			checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			"9",
			&valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"9": {
							Value: 80.0,
						},
					},
				},
			},
			[]Metric{
				// ((5000000 * 8) / (80 * 1000000)) * 100 = 50.0
				{"snmp.ifBandwidthInUsage.rate", 50.0},
			},
		},
		{
			"should complete even on error",
			checkconfig.SymbolConfig{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets"},
			"9",
			&valuestore.ResultValueStore{
				ColumnValues: valuestore.ColumnResultValuesType{
					// ifHCInOctets
					"1.3.6.1.2.1.31.1.1.1.6": map[string]valuestore.ResultValue{
						"9": {
							Value: 5000000.0,
						},
					},
					// ifHCOutOctets
					"1.3.6.1.2.1.31.1.1.1.10": map[string]valuestore.ResultValue{
						"9": {
							Value: 1000000.0,
						},
					},
					// ifHighSpeed
					"1.3.6.1.2.1.31.1.1.1.15": map[string]valuestore.ResultValue{
						"999": {
							Value: 80.0,
						},
					},
				},
			},
			[]Metric{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := mocksender.NewMockSender("testID") // required to initiate aggregator
			sender.On("Rate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

			ms := &MetricSender{
				sender: sender,
			}
			tags := []string{"foo:bar"}
			ms.trySendBandwidthUsageMetric(tt.symbol, tt.fullIndex, tt.values, tags, nil)

			for _, metric := range tt.expectedMetric {
				sender.AssertMetric(t, "Rate", metric.name, metric.value, "", tags)
			}
		})
	}
}
