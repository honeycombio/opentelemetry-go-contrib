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

package launcher

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
)

//revive:disable:import-shadowing this is a test file

const (
	expectedTracingDisabledMessage = "tracing is disabled by configuration: no endpoint set"
	expectedMetricsDisabledMessage = "metrics are disabled by configuration: no endpoint set"
)

type testLogger struct {
	output []string
}

func (logger *testLogger) addOutput(output string) {
	logger.output = append(logger.output, output)
}

func (logger *testLogger) Fatalf(format string, v ...interface{}) {
	logger.addOutput(fmt.Sprintf(format, v...))
}

func (logger *testLogger) Debugf(format string, v ...interface{}) {
	logger.addOutput(fmt.Sprintf(format, v...))
}

func (logger *testLogger) requireContains(t *testing.T, expected string) {
	t.Helper()
	for _, output := range logger.output {
		if strings.Contains(output, expected) {
			return
		}
	}

	t.Errorf("\nString unexpectedly not found: %v\nIn: %v", expected, logger.output)
}

func (logger *testLogger) requireNotContains(t *testing.T, expected string) {
	t.Helper()
	for _, output := range logger.output {
		if strings.Contains(output, expected) {
			t.Errorf("\nString unexpectedly found: %v\nIn: %v", expected, logger.output)
			return
		}
	}
}

// Create some dummy server implementations so that we can
// spin up tests that don't need to wait for a timeout trying to send data.
type dummyTraceServer struct {
	collectortrace.UnimplementedTraceServiceServer
}

func (*dummyTraceServer) Export(ctx context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	fmt.Println("inside trace export", time.Now().Format(time.RFC3339))
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

type dummyMetricsServer struct {
	collectormetrics.UnimplementedMetricsServiceServer
}

func (*dummyMetricsServer) Export(ctx context.Context, req *collectormetrics.ExportMetricsServiceRequest) (*collectormetrics.ExportMetricsServiceResponse, error) {
	fmt.Println("inside metrics export", time.Now().Format(time.RFC3339))
	return &collectormetrics.ExportMetricsServiceResponse{}, nil
}

// dummyGRPCListener is a test helper that builds a dummy grpc server that does nothing but
// returns quickly so that we don't have to wait for timeouts
func dummyGRPCListener() func() {
	grpcServer := grpc.NewServer()
	collectortrace.RegisterTraceServiceServer(grpcServer, &dummyTraceServer{})
	collectormetrics.RegisterMetricsServiceServer(grpcServer, &dummyMetricsServer{})

	// we need to listen on localhost, not 0.0.0.0, to satisfy JAMF without causing problems
	l, err := net.Listen("tcp", net.JoinHostPort("localhost", "4317"))
	if err != nil {
		panic("oops - dummyGrpcListener failed to start up!")
	}
	go grpcServer.Serve(l)
	return grpcServer.Stop
}

// withTestExporters conforms to the Option interface and sets up the options needed
// to prevent a test from having to time out. It won't work unless the test also does this:
//
// stopper := dummyGRPCListener()
// defer stopper()
func withTestExporters() Option {
	return func(c *Config) {
		WithSpanExporterEndpoint("localhost:4317")(c)
		WithSpanExporterInsecure(true)(c)
		WithMetricExporterEndpoint("localhost:4317")(c)
		WithMetricExporterInsecure(true)(c)
	}
}

type testErrorHandler struct {
}

func (t *testErrorHandler) Handle(err error) {
	fmt.Printf("test error handler handled error: %v\n", err)
}

// TODO REVIEW TEST - want default service name anyway
// func TestInvalidServiceName(t *testing.T) {
// 	logger := &testLogger{}
// 	shutdown, _ := ConfigureOpenTelemetry(WithLogger(logger))
// 	defer shutdown()

// 	expected := "invalid configuration: service name missing"
// 	logger.requireContains(t, expected)
// }

func testEndpointDisabled(t *testing.T, expected string, opts ...Option) {
	logger := &testLogger{}
	shutdown, _ := ConfigureOpenTelemetry(
		append(opts,
			WithLogger(logger),
			WithServiceName("test-service"),
			WithMetricsEnabled(false),
		)...,
	)
	defer shutdown()

	logger.requireContains(t, expected)
}

func TestTraceEndpointDisabled(t *testing.T) {
	testEndpointDisabled(
		t,
		expectedTracingDisabledMessage,
		WithSpanExporterEndpoint(""),
	)
}

func TestMetricEndpointDisabled(t *testing.T) {
	testEndpointDisabled(
		t,
		expectedMetricsDisabledMessage,
		WithMetricExporterEndpoint(""),
	)
}

func TestValidConfig(t *testing.T) {
	logger := &testLogger{}

	// in order for tests to not have to timeout during
	// the shutdown call, we must direct them to a running
	// server, which means that it has to go to localhost:4317,
	// and it must be Insecure.
	stopper := dummyGRPCListener()
	defer stopper()

	fmt.Println("before config", time.Now().Format(time.RFC3339))
	shutdown, _ := ConfigureOpenTelemetry(
		WithLogger(logger),
		WithServiceName("test-service"),
		withTestExporters(),
	)
	defer shutdown()

	if len(logger.output) > 0 {
		t.Errorf("\nExpected: no logs\ngot: %v", logger.output)
	}
}

func TestInvalidEnvironment(t *testing.T) {
	setenv("OTEL_EXPORTER_OTLP_METRICS_INSECURE", "bleargh")

	logger := &testLogger{}
	shutdown, _ := ConfigureOpenTelemetry(
		WithLogger(logger),
		WithServiceName("test-service"),
	)
	defer shutdown()

	logger.requireContains(t, "environment error")
	unsetEnvironment()
}

func TestInvalidMetricsPushIntervalEnv(t *testing.T) {
	setenv("OTEL_EXPORTER_OTLP_METRICS_PERIOD", "300million")

	logger := &testLogger{}
	shutdown, _ := ConfigureOpenTelemetry(
		WithLogger(logger),
		WithServiceName("test-service"),
		withTestExporters(),
	)
	defer shutdown()

	logger.requireContains(t, "setup error: invalid metric reporting period")
	unsetEnvironment()
}

func TestInvalidMetricsPushIntervalConfig(t *testing.T) {
	logger := &testLogger{}
	shutdown, _ := ConfigureOpenTelemetry(
		WithLogger(logger),
		WithServiceName("test-service"),
		WithSpanExporterEndpoint("localhost:4317"),
		WithMetricExporterEndpoint("localhost:4317"),
		WithMetricReportingPeriod(-time.Second),
	)
	defer shutdown()

	logger.requireContains(t, "setup error: invalid metric reporting period")
	unsetEnvironment()
}

func TestDebugEnabled(t *testing.T) {
	logger := &testLogger{}
	stopper := dummyGRPCListener()
	defer stopper()

	shutdown, _ := ConfigureOpenTelemetry(
		WithLogger(logger),
		WithServiceName("test-service"),
		withTestExporters(),
		WithLogLevel("debug"),
		WithResourceAttributes(map[string]string{
			"attr1":     "val1",
			"host.name": "host456",
		}),
	)
	defer shutdown()
	output := strings.Join(logger.output[:], ",")
	assert.Contains(t, output, "debug logging enabled")
	assert.Contains(t, output, "test-service")
	assert.Contains(t, output, "localhost:4317")
	assert.Contains(t, output, "attr1")
	assert.Contains(t, output, "val1")
	assert.Contains(t, output, "host.name")
	assert.Contains(t, output, "host456")
}

// TODO Review test - service version funky
func TestDefaultConfig(t *testing.T) {
	logger := &testLogger{}
	handler := &testErrorHandler{}
	config := newConfig(
		WithLogger(logger),
		WithErrorHandler(handler),
	)

	attributes := []attribute.KeyValue{
		attribute.String("host.name", host()),
		attribute.String("service.version", "unknown"),
		attribute.String("telemetry.sdk.name", "launcher"),
		attribute.String("telemetry.sdk.language", "go"),
		attribute.String("telemetry.sdk.version", version),
	}

	expected := &Config{
		TracesExporterEndpoint:          "localhost:4317",
		TracesExporterEndpointInsecure:  false,
		TracesEnabled:                   true,
		ServiceName:                     "",
		ServiceVersion:                  "unknown",
		MetricsExporterEndpoint:         "localhost:4317",
		MetricsExporterEndpointInsecure: false,
		MetricsEnabled:                  true,
		MetricsReportingPeriod:          "30s",
		LogLevel:                        "info",
		Headers:                         map[string]string{},
		ResourceAttributes:              map[string]string{},
		Propagators:                     []string{"tracecontext", "baggage"},
		Resource:                        resource.NewWithAttributes(semconv.SchemaURL, attributes...),
		Logger:                          logger,
		errorHandler:                    handler,
	}
	assert.Equal(t, expected, config)
}

func TestEnvironmentVariables(t *testing.T) {
	setEnvironment()
	logger := &testLogger{}
	handler := &testErrorHandler{}
	config := newConfig(
		WithLogger(logger),
		WithErrorHandler(handler),
	)

	attributes := []attribute.KeyValue{
		attribute.String("host.name", host()),
		attribute.String("service.name", "test-service-name"),
		attribute.String("service.version", "test-service-version"),
		attribute.String("telemetry.sdk.name", "launcher"),
		attribute.String("telemetry.sdk.language", "go"),
		attribute.String("telemetry.sdk.version", version),
	}

	expected := &Config{
		TracesExporterEndpoint:          "satellite-url",
		TracesExporterEndpointInsecure:  true,
		TracesEnabled:                   true,
		ServiceName:                     "test-service-name",
		ServiceVersion:                  "test-service-version",
		MetricsExporterEndpoint:         "metrics-url",
		MetricsExporterEndpointInsecure: true,
		MetricsEnabled:                  false,
		MetricsReportingPeriod:          "30s",
		LogLevel:                        "debug",
		Headers:                         map[string]string{},
		ResourceAttributes:              map[string]string{},
		ResourceAttributesFromEnv:       "service.name=test-service-name-b",
		Propagators:                     []string{"b3", "w3c"},
		Resource:                        resource.NewWithAttributes(semconv.SchemaURL, attributes...),
		Logger:                          logger,
		errorHandler:                    handler,
	}
	assert.Equal(t, expected, config)
	unsetEnvironment()
}

func TestConfigurationOverrides(t *testing.T) {
	setEnvironment()
	logger := &testLogger{}
	handler := &testErrorHandler{}
	config := newConfig(
		WithServiceName("override-service-name"),
		WithServiceVersion("override-service-version"),
		WithSpanExporterEndpoint("override-satellite-url"),
		WithSpanExporterInsecure(false),
		WithMetricExporterEndpoint("override-metrics-url"),
		WithMetricExporterInsecure(false),
		WithLogLevel("info"),
		WithLogger(logger),
		WithErrorHandler(handler),
		WithPropagators([]string{"b3"}),
	)

	attributes := []attribute.KeyValue{
		attribute.String("host.name", host()),
		attribute.String("service.name", "override-service-name"),
		attribute.String("service.version", "override-service-version"),
		attribute.String("telemetry.sdk.name", "launcher"),
		attribute.String("telemetry.sdk.language", "go"),
		attribute.String("telemetry.sdk.version", version),
	}

	expected := &Config{
		ServiceName:                     "override-service-name",
		ServiceVersion:                  "override-service-version",
		TracesExporterEndpoint:          "override-satellite-url",
		TracesExporterEndpointInsecure:  false,
		TracesEnabled:                   true,
		MetricsExporterEndpoint:         "override-metrics-url",
		MetricsExporterEndpointInsecure: false,
		MetricsReportingPeriod:          "30s",
		LogLevel:                        "info",
		Headers:                         map[string]string{},
		ResourceAttributes:              map[string]string{},
		ResourceAttributesFromEnv:       "service.name=test-service-name-b",
		Propagators:                     []string{"b3"},
		Resource:                        resource.NewWithAttributes(semconv.SchemaURL, attributes...),
		Logger:                          logger,
		errorHandler:                    handler,
	}
	assert.Equal(t, expected, config)
	unsetEnvironment()
}

type TestCarrier struct {
	values map[string]string
}

func (t TestCarrier) Keys() []string {
	keys := make([]string, 0, len(t.values))
	for k := range t.values {
		keys = append(keys, k)
	}
	return keys
}

func (t TestCarrier) Get(key string) string {
	return t.values[key]
}

func (t TestCarrier) Set(key string, value string) {
	t.values[key] = value
}

func TestConfigurePropagators1(t *testing.T) {
	stopper := dummyGRPCListener()
	defer stopper()

	mem1, _ := baggage.NewMember("keyone", "foo1")
	mem2, _ := baggage.NewMember("keytwo", "bar1")
	bag, _ := baggage.New(mem1, mem2)

	ctx := baggage.ContextWithBaggage(context.Background(), bag)

	unsetEnvironment()
	logger := &testLogger{}
	shutdown, err := ConfigureOpenTelemetry(
		WithLogger(logger),
		WithServiceName("test-service"),
		withTestExporters(),
	)
	assert.NoError(t, err)
	defer shutdown()

	ctx, finish := otel.Tracer("sampletracer").Start(ctx, "foo")
	defer finish.End()

	carrier := TestCarrier{values: map[string]string{}}
	prop := otel.GetTextMapPropagator()
	prop.Inject(ctx, carrier)
	baggage := carrier.Get("baggage")
	assert.Contains(t, baggage, "keyone=foo1")
	assert.Contains(t, baggage, "keytwo=bar1")
	assert.Greater(t, len(carrier.Get("traceparent")), 0)
}

func TestConfigurePropagators2(t *testing.T) {
	stopper := dummyGRPCListener()
	defer stopper()

	mem1, _ := baggage.NewMember("keyone", "foo1")
	mem2, _ := baggage.NewMember("keytwo", "bar1")
	bag, _ := baggage.New(mem1, mem2)

	ctx := baggage.ContextWithBaggage(context.Background(), bag)

	unsetEnvironment()
	logger := &testLogger{}
	shutdown, err := ConfigureOpenTelemetry(
		WithLogger(logger),
		WithServiceName("test-service"),
		WithPropagators([]string{"b3", "baggage", "tracecontext"}),
		withTestExporters(),
	)
	assert.NoError(t, err)
	defer shutdown()

	ctx, finish := otel.Tracer("sampletracer").Start(ctx, "foo")
	defer finish.End()

	carrier := TestCarrier{values: map[string]string{}}
	prop := otel.GetTextMapPropagator()
	prop.Inject(ctx, carrier)
	assert.Greater(t, len(carrier.Get("x-b3-traceid")), 0)
	baggage := carrier.Get("baggage")
	assert.Contains(t, baggage, "keyone=foo1")
	assert.Contains(t, baggage, "keytwo=bar1")
	assert.Greater(t, len(carrier.Get("traceparent")), 0)
}

func TestConfigurePropagators3(t *testing.T) {
	stopper := dummyGRPCListener()
	defer stopper()

	unsetEnvironment()
	logger := &testLogger{}
	shutdown, err := ConfigureOpenTelemetry(
		WithLogger(logger),
		WithServiceName("test-service"),
		WithPropagators([]string{"invalid"}),
		withTestExporters(),
	)
	assert.NoError(t, err)
	defer shutdown()

	expected := "invalid configuration: unsupported propagators. Supported options: b3,baggage,tracecontext,ottrace"
	if !strings.Contains(logger.output[0], expected) {
		t.Errorf("\nString not found: %v\nIn: %v", expected, logger.output[0])
	}
}

func host() string {
	host, _ := os.Hostname()
	return host
}

func TestConfigureResourcesAttributes(t *testing.T) {
	setenv("OTEL_RESOURCE_ATTRIBUTES", "label1=value1,label2=value2")
	config := Config{
		ServiceName:    "test-service",
		ServiceVersion: "test-version",
	}
	resource := newResource(&config)
	expected := []attribute.KeyValue{
		attribute.String("host.name", host()),
		attribute.String("label1", "value1"),
		attribute.String("label2", "value2"),
		attribute.String("service.name", "test-service"),
		attribute.String("service.version", "test-version"),
		attribute.String("telemetry.sdk.language", "go"),
		attribute.String("telemetry.sdk.name", "launcher"),
		attribute.String("telemetry.sdk.version", version),
	}
	assert.Equal(t, expected, resource.Attributes())

	setenv("OTEL_RESOURCE_ATTRIBUTES", "telemetry.sdk.language=test-language")
	config = Config{
		ServiceName:    "test-service",
		ServiceVersion: "test-version",
	}
	resource = newResource(&config)
	expected = []attribute.KeyValue{
		attribute.String("host.name", host()),
		attribute.String("service.name", "test-service"),
		attribute.String("service.version", "test-version"),
		attribute.String("telemetry.sdk.language", "go"),
		attribute.String("telemetry.sdk.name", "launcher"),
		attribute.String("telemetry.sdk.version", version),
	}
	assert.Equal(t, expected, resource.Attributes())

	setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=test-service-b,host.name=host123")
	config = Config{
		ServiceName:    "test-service-b",
		ServiceVersion: "test-version",
	}
	resource = newResource(&config)
	expected = []attribute.KeyValue{
		attribute.String("host.name", "host123"),
		attribute.String("service.name", "test-service-b"),
		attribute.String("service.version", "test-version"),
		attribute.String("telemetry.sdk.language", "go"),
		attribute.String("telemetry.sdk.name", "launcher"),
		attribute.String("telemetry.sdk.version", version),
	}
	assert.Equal(t, expected, resource.Attributes())
}

func TestServiceNameViaResourceAttributes(t *testing.T) {
	stopper := dummyGRPCListener()
	defer stopper()

	setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=test-service-b")
	logger := &testLogger{}
	shutdown, _ := ConfigureOpenTelemetry(
		WithLogger(logger),
		withTestExporters(),
	)
	defer shutdown()

	notExpected := "invalid configuration: service name missing"
	logger.requireNotContains(t, notExpected)
}

func TestEmptyHostnameDefaultsToOsHostname(t *testing.T) {
	stopper := dummyGRPCListener()
	defer stopper()

	setenv("OTEL_RESOURCE_ATTRIBUTES", "host.name=")
	shutdown, _ := ConfigureOpenTelemetry(
		WithServiceName("test-service"),
		WithSpanExporterEndpoint("localhost:443"),
		WithResourceAttributes(map[string]string{
			"attr1":     "val1",
			"host.name": "",
		}),
		WithShutdown(func(c *Config) error {
			attrs := attribute.NewSet(c.Resource.Attributes()...)
			v, ok := attrs.Value("host.name")
			assert.Equal(t, host(), v.AsString())
			assert.True(t, ok)
			return nil
		}),
		withTestExporters(),
	)
	defer shutdown()
}

func TestConfigWithResourceAttributes(t *testing.T) {
	stopper := dummyGRPCListener()
	defer stopper()

	shutdown, _ := ConfigureOpenTelemetry(
		WithServiceName("test-service"),
		WithSpanExporterEndpoint("localhost:443"),
		WithResourceAttributes(map[string]string{
			"attr1": "val1",
			"attr2": "val2",
		}),
		WithShutdown(func(c *Config) error {
			attrs := attribute.NewSet(c.Resource.Attributes()...)
			v, ok := attrs.Value("attr1")
			assert.Equal(t, "val1", v.AsString())
			assert.True(t, ok)

			v, ok = attrs.Value("attr2")
			assert.Equal(t, "val2", v.AsString())
			assert.True(t, ok)
			return nil
		}),
		withTestExporters(),
	)
	defer shutdown()
}

// this is to stop the linter from complaining
func setenv(key string, value string) {
	_ = os.Setenv(key, value)
}

func setEnvironment() {
	setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "satellite-url")
	setenv("OTEL_EXPORTER_OTLP_TRACES_INSECURE", "true")
	setenv("OTEL_SERVICE_NAME", "test-service-name")
	setenv("OTEL_SERVICE_VERSION", "test-service-version")
	setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "metrics-url")
	setenv("OTEL_EXPORTER_OTLP_METRICS_INSECURE", "true")
	setenv("OTEL_METRICS_ENABLED", "false")
	setenv("OTEL_LOG_LEVEL", "debug")
	setenv("OTEL_PROPAGATORS", "b3,w3c")
	setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=test-service-name-b")
}

func unsetEnvironment() {
	vars := []string{
		"OTEL_SERVICE_NAME",
		"OTEL_SERVICE_VERSION",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_INSECURE",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_INSECURE",
		"OTEL_LOG_LEVEL",
		"OTEL_PROPAGATORS",
		"OTEL_RESOURCE_ATTRIBUTES",
		"OTEL_EXPORTER_OTLP_METRICS_PERIOD",
		"OTEL_METRICS_ENABLED",
	}
	for _, envvar := range vars {
		_ = os.Unsetenv(envvar)
	}
}

func TestMain(m *testing.M) {
	unsetEnvironment()
	os.Exit(m.Run())
}
