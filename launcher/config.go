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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/open-telemetry/opentelemetry-go-contrib/launcher/pipelines"
	"github.com/sethvargo/go-envconfig"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
)

var (
	SetVendorOptions func() []Option
	ValidateConfig   func(*Config) error
)

type Option func(*Config)

// WithMetricExporterEndpoint configures the endpoint for sending metrics via OTLP
func WithMetricExporterEndpoint(url string) Option {
	return func(c *Config) {
		c.MetricsExporterEndpoint = url
	}
}

// WithSpanExporterEndpoint configures the endpoint for sending traces via OTLP
func WithSpanExporterEndpoint(url string) Option {
	return func(c *Config) {
		c.TracesExporterEndpoint = url
	}
}

// WithServiceName configures a "service.name" resource label
func WithServiceName(name string) Option {
	return func(c *Config) {
		c.ServiceName = name
	}
}

// WithServiceVersion configures a "service.version" resource label
func WithServiceVersion(version string) Option {
	return func(c *Config) {
		c.ServiceVersion = version
	}
}

// WithHeaders configures OTLP/gRPC connection headers
func WithHeaders(headers map[string]string) Option {
	return func(c *Config) {
		if c.Headers == nil {
			c.Headers = make(map[string]string)
		}
		for k, v := range headers {
			c.Headers[k] = v
		}
	}
}

// WithLogLevel configures the logging level for OpenTelemetry
func WithLogLevel(loglevel string) Option {
	return func(c *Config) {
		c.LogLevel = loglevel
	}
}

// WithSpanExporterInsecure permits connecting to the
// trace endpoint without a certificate
func WithSpanExporterInsecure(insecure bool) Option {
	return func(c *Config) {
		c.TracesExporterEndpointInsecure = insecure
	}
}

// WithMetricExporterInsecure permits connecting to the
// metric endpoint without a certificate
func WithMetricExporterInsecure(insecure bool) Option {
	return func(c *Config) {
		c.MetricsExporterEndpointInsecure = insecure
	}
}

// WithResourceAttributes configures attributes on the resource
func WithResourceAttributes(attributes map[string]string) Option {
	return func(c *Config) {
		c.ResourceAttributes = attributes
	}
}

// WithPropagators configures propagators
func WithPropagators(propagators []string) Option {
	return func(c *Config) {
		c.Propagators = propagators
	}
}

// Configures a global error handler to be used throughout an OpenTelemetry instrumented project.
// See "go.opentelemetry.io/otel"
func WithErrorHandler(handler otel.ErrorHandler) Option {
	return func(c *Config) {
		c.errorHandler = handler
	}
}

// WithMetricReportingPeriod configures the metric reporting period,
// how often the controller collects and exports metric data.
func WithMetricReportingPeriod(p time.Duration) Option {
	return func(c *Config) {
		c.MetricReportingPeriod = fmt.Sprint(p)
	}
}

// WithMetricEnabled configures whether metrics should be enabled
func WithMetricsEnabled(enabled bool) Option {
	return func(c *Config) {
		c.MetricsEnabled = enabled
	}
}

// WithTracesEnabled configures whether traces should be enabled
func WithTracesEnabled(enabled bool) Option {
	return func(c *Config) {
		c.TracesEnabled = enabled
	}
}

// WithSpanProcessor adds one or more SpanProcessors
func WithSpanProcessor(sp ...trace.SpanProcessor) Option {
	return func(c *Config) {
		c.SpanProcessors = append(c.SpanProcessors, sp...)
	}
}

// WithShutdown adds functions that will be called first when the shutdown function is called.
// They are given a copy of the Config object (which has access to the Logger), and should
// return an error only in extreme circumstances, as an error return here is immediately fatal.
func WithShutdown(f func(c *Config) error) Option {
	return func(c *Config) {
		c.ShutdownFunctions = append(c.ShutdownFunctions, f)
	}
}

type Logger interface {
	Fatalf(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}

func WithLogger(logger Logger) Option {
	return func(c *Config) {
		c.Logger = logger
	}
}

type DefaultLogger struct {
}

func (l *DefaultLogger) Fatalf(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}

func (l *DefaultLogger) Debugf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

type defaultHandler struct {
	logger Logger
}

func (l *defaultHandler) Handle(err error) {
	l.logger.Debugf("error: %v\n", err)
}

type Config struct {
	TracesExporterEndpoint          string `env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,default=localhost:4317"`
	TracesExporterEndpointInsecure  bool   `env:"OTEL_EXPORTER_OTLP_TRACES_INSECURE,default=false"`
	TracesEnabled                   bool   `env:"OTEL_TRACES_ENABLED,default=true"`
	ServiceName                     string `env:"OTEL_SERVICE_NAME"`
	ServiceVersion                  string `env:"OTEL_SERVICE_VERSION"`
	Headers                         map[string]string
	HeadersFromEnv                  string   `env:"OTEL_EXPORTER_OTLP_HEADERS"`
	MetricsExporterEndpoint         string   `env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT,default=localhost:4317"`
	MetricsExporterEndpointInsecure bool     `env:"OTEL_EXPORTER_OTLP_METRICS_INSECURE,default=false"`
	MetricsEnabled                  bool     `env:"OTEL_METRICS_ENABLED,default=true"`
	MetricReportingPeriod           string   `env:"OTEL_EXPORTER_OTLP_METRIC_PERIOD,default=30s"`
	LogLevel                        string   `env:"OTEL_LOG_LEVEL,default=info"`
	Propagators                     []string `env:"OTEL_PROPAGATORS,default=tracecontext,baggage"`
	ResourceAttributes              map[string]string
	ResourceAttributesFromEnv       string `env:"OTEL_RESOURCE_ATTRIBUTES"`

	SpanProcessors    []trace.SpanProcessor
	Resource          *resource.Resource
	Logger            Logger
	ShutdownFunctions []func(c *Config) error
	errorHandler      otel.ErrorHandler
}

func newConfig(opts ...Option) *Config {
	c := &Config{
		Headers:            map[string]string{},
		ResourceAttributes: map[string]string{},
	}
	envError := envconfig.Process(context.Background(), c)
	c.Logger = &DefaultLogger{}
	c.errorHandler = &defaultHandler{logger: c.Logger}
	if envError != nil {
		c.Logger.Fatalf("environment error: %v", envError)
	}

	// If a vendor has specific options to add, add them to opts
	vendorOpts := []Option{}
	if SetVendorOptions != nil {
		vendorOpts = append(vendorOpts, SetVendorOptions()...)
	}

	// apply vendor options then user options
	for _, opt := range append(vendorOpts, opts...) {
		opt(c)
	}

	if len(c.HeadersFromEnv) > 0 {
		c.Headers = getHeadersFromEnv(c)
	}
	c.Resource = newResource(c)
	return c
}

type Launcher struct {
	config        *Config
	shutdownFuncs []func() error
}

// these are set as key=value, not key:value
func getHeadersFromEnv(c *Config) map[string]string {
	if c.HeadersFromEnv == "" {
		return nil
	}
	HeadersFromEnv := strings.Split(c.HeadersFromEnv, ",")
	mapHeaders := make(map[string]string)
	for _, e := range HeadersFromEnv {
		headers := strings.Split(e, "=")
		mapHeaders[headers[0]] = headers[1]
	}
	return mapHeaders
}

// these are set as key=value, not key:value
func getResourceAttrsFromEnv(c *Config) map[string]string {
	if c.ResourceAttributesFromEnv == "" {
		return nil
	}
	ResourceAttrsFromEnv := strings.Split(c.ResourceAttributesFromEnv, ",")
	mapResourceAttrs := make(map[string]string)
	for _, e := range ResourceAttrsFromEnv {
		resourceAttrs := strings.Split(e, "=")
		mapResourceAttrs[resourceAttrs[0]] = resourceAttrs[1]
	}
	return mapResourceAttrs
}

func newResource(c *Config) *resource.Resource {
	r := resource.Environment()

	c.ResourceAttributes = getResourceAttrsFromEnv(c)
	hostnameSet := false
	for iter := r.Iter(); iter.Next(); {
		if iter.Attribute().Key == semconv.HostNameKey && len(iter.Attribute().Value.Emit()) > 0 {
			hostnameSet = true
		}
	}

	attributes := []attribute.KeyValue{
		semconv.TelemetrySDKNameKey.String("launcher"),
		semconv.TelemetrySDKLanguageGo,
		semconv.TelemetrySDKVersionKey.String(version),
	}

	if len(c.ServiceName) > 0 {
		attributes = append(attributes, semconv.ServiceNameKey.String(c.ServiceName))
	}

	if len(c.ServiceVersion) > 0 {
		attributes = append(attributes, semconv.ServiceVersionKey.String(c.ServiceVersion))
	}

	for key, value := range c.ResourceAttributes {
		if len(value) > 0 {
			if key == string(semconv.HostNameKey) {
				hostnameSet = true
			}
			attributes = append(attributes, attribute.String(key, value))
		}
	}

	if !hostnameSet {
		hostname, err := os.Hostname()
		if err != nil {
			c.Logger.Debugf("unable to set host.name. Set OTEL_RESOURCE_ATTRIBUTES=\"host.name=<your_host_name>\" env var or configure WithResourceAttributes in code: %v", err)
		} else {
			attributes = append(attributes, semconv.HostNameKey.String(hostname))
		}
	}

	attributes = append(r.Attributes(), attributes...)

	// These detectors can't actually fail, ignoring the error.
	r, _ = resource.New(
		context.Background(),
		resource.WithSchemaURL(semconv.SchemaURL),
		resource.WithAttributes(attributes...),
	)

	// Note: There are new detectors we may wish to take advantage
	// of, now available in the default SDK (e.g., WithProcess(),
	// WithOSType(), ...).
	return r
}

type setupFunc func(Config) (func() error, error)

func setupTracing(c Config) (func() error, error) {
	if !c.TracesEnabled || c.TracesExporterEndpoint == "" {
		c.Logger.Debugf("tracing is disabled by configuration: no endpoint set")
		return nil, nil
	}
	return pipelines.NewTracePipeline(pipelines.PipelineConfig{
		Endpoint:       c.TracesExporterEndpoint,
		Insecure:       c.TracesExporterEndpointInsecure,
		Headers:        c.Headers,
		Resource:       c.Resource,
		Propagators:    c.Propagators,
		SpanProcessors: c.SpanProcessors,
	})
}

func setupMetrics(c Config) (func() error, error) {
	if !c.MetricsEnabled || c.MetricsExporterEndpoint == "" {
		c.Logger.Debugf("metrics are disabled by configuration: no endpoint set")
		return nil, nil
	}
	return pipelines.NewMetricsPipeline(pipelines.PipelineConfig{
		Endpoint:        c.MetricsExporterEndpoint,
		Insecure:        c.MetricsExporterEndpointInsecure,
		Headers:         c.Headers,
		Resource:        c.Resource,
		ReportingPeriod: c.MetricReportingPeriod,
	})
}

func ConfigureOpenTelemetry(opts ...Option) (func(), error) {
	c := newConfig(opts...)

	if c.LogLevel == "debug" {
		c.Logger.Debugf("debug logging enabled")
		c.Logger.Debugf("configuration")
		s, _ := json.MarshalIndent(c, "", "\t")
		c.Logger.Debugf(string(s))
	}

	// Give a vendor a chance to validate the configuration
	if ValidateConfig != nil {
		if err := ValidateConfig(c); err != nil {
			return nil, err
		}
	}

	if c.errorHandler != nil {
		otel.SetErrorHandler(c.errorHandler)
	}

	launcher := Launcher{
		config: c,
	}

	for _, setup := range []setupFunc{setupTracing, setupMetrics} {
		shutdown, err := setup(*c)
		if err != nil {
			c.Logger.Fatalf("setup error: %v", err)
			continue
		}
		if shutdown != nil {
			launcher.shutdownFuncs = append(launcher.shutdownFuncs, shutdown)
		}
	}
	return launcher.Shutdown, nil
}

func (ls Launcher) Shutdown() {
	// call config shutdown functions first
	for _, shutdown := range ls.config.ShutdownFunctions {
		err := shutdown(ls.config)
		if err != nil {
			ls.config.Logger.Fatalf("failed to stop exporter while calling config shutdown: %v", err)
		}
	}

	for _, shutdown := range ls.shutdownFuncs {
		if err := shutdown(); err != nil {
			ls.config.Logger.Fatalf("failed to stop exporter: %v", err)
		}
	}
}
