// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pipelines

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	hostMetrics "go.opentelemetry.io/contrib/instrumentation/host"
	runtimeMetrics "go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	metricglobal "go.opentelemetry.io/otel/metric/global"
	controller "go.opentelemetry.io/otel/sdk/metric/controller/basic"
	processor "go.opentelemetry.io/otel/sdk/metric/processor/basic"
	selector "go.opentelemetry.io/otel/sdk/metric/selector/simple"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
)

// NewMetricsPipeline takes a PipelineConfig and builds a metrics pipeline.
// It returns a shutdown function that should be called when terminating the pipeline.
func NewMetricsPipeline(c PipelineConfig) (func() error, error) {
	metricExporter, err := newMetricsExporter(c.Protocol, c.Endpoint, c.Insecure, c.Headers)
	if err != nil {
		return nil, fmt.Errorf("failed to create metric exporter: %v", err)
	}

	period := controller.DefaultPeriod
	if c.ReportingPeriod != "" {
		period, err = time.ParseDuration(c.ReportingPeriod)
		if err != nil {
			return nil, fmt.Errorf("invalid metric reporting period: %v", err)
		}
		if period <= 0 {
			return nil, fmt.Errorf("invalid metric reporting period: %v", c.ReportingPeriod)
		}
	}
	pusher := controller.New(
		processor.NewFactory(
			selector.NewWithInexpensiveDistribution(),
			metricExporter,
		),
		controller.WithExporter(metricExporter),
		controller.WithResource(c.Resource),
		controller.WithCollectPeriod(period),
	)

	if err = pusher.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to start controller: %v", err)
	}

	if err = runtimeMetrics.Start(runtimeMetrics.WithMeterProvider(pusher)); err != nil {
		return nil, fmt.Errorf("failed to start runtime metrics: %v", err)
	}

	if err = hostMetrics.Start(hostMetrics.WithMeterProvider(pusher)); err != nil {
		return nil, fmt.Errorf("failed to start host metrics: %v", err)
	}

	metricglobal.SetMeterProvider(pusher)
	return func() error {
		_ = pusher.Stop(context.Background())
		return metricExporter.Shutdown(context.Background())
	}, nil
}

//revive:disable:flag-parameter bools are fine for an internal function
func newMetricsExporter(protocol Protocol, endpoint string, insecure bool, headers map[string]string) (*otlpmetric.Exporter, error) {
	switch protocol {
	case "grpc":
		return newGRPCMetricsExporter(endpoint, insecure, headers)
	case "http/protobuf":
		return newHTTPMetricsExporter(endpoint, insecure, headers)
	case "http/json":
		return nil, errors.New("http/json is currently unsupported by this launcher")
	default:
		return nil, errors.New("'" + string(protocol) + "' is not a supported protocol")
	}
}

func newGRPCMetricsExporter(endpoint string, insecure bool, headers map[string]string) (*otlpmetric.Exporter, error) {
	secureOption := otlpmetricgrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, ""))
	if insecure {
		secureOption = otlpmetricgrpc.WithInsecure()
	}
	return otlpmetric.New(
		context.Background(),
		otlpmetricgrpc.NewClient(
			secureOption,
			otlpmetricgrpc.WithEndpoint(endpoint),
			otlpmetricgrpc.WithHeaders(headers),
			otlpmetricgrpc.WithCompressor(gzip.Name),
		),
	)
}

func newHTTPMetricsExporter(endpoint string, insecure bool, headers map[string]string) (*otlpmetric.Exporter, error) {
	tlsconfig := &tls.Config{}
	secureOption := otlpmetrichttp.WithTLSClientConfig(tlsconfig)
	if insecure {
		secureOption = otlpmetrichttp.WithInsecure()
	}
	if insecure {
		secureOption = otlpmetrichttp.WithInsecure()
	}
	return otlpmetric.New(
		context.Background(),
		otlpmetrichttp.NewClient(
			secureOption,
			otlpmetrichttp.WithEndpoint(endpoint),
			otlpmetrichttp.WithHeaders(headers),
			otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression),
		),
	)
}
