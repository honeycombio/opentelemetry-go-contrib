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
	"time"

	// TODO: before merging, update to "go.opentelemetry.io/contrib/launcher".
	"github.com/honeycombio/opentelemetry-go-contrib/launcher/pipelines"
	"github.com/sethvargo/go-envconfig"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
)

var (
	// SetVendorOptions provides a way for a vendor to add a set of Options that are automatically applied.
	SetVendorOptions func() []Option
	// ValidateConfig is a function that a vendor can implement to provide additional validation after
	// a configuration is built.
	ValidateConfig func(*Config) error
)

// Option is the type of an Option to the ConfigureOpenTelemetry function; it's a
// function that accepts a config and modifies it.
type Option func(*Config)

// WithMetricExporterEndpoint configures the endpoint for sending metrics via OTLP.
func WithMetricExporterEndpoint(url string) Option {
	return func(c *Config) {
		c.MetricsExporterEndpoint = url
	}
}

// WithSpanExporterEndpoint configures the endpoint for sending traces via OTLP.
func WithSpanExporterEndpoint(url string) Option {
	return func(c *Config) {
		c.TracesExporterEndpoint = url
	}
}

// WithServiceName configures a "service.name" resource label.
func WithServiceName(name string) Option {
	return func(c *Config) {
		c.ServiceName = name
	}
}

// WithServiceVersion configures a "service.version" resource label.
func WithServiceVersion(version string) Option {
	return func(c *Config) {
		c.ServiceVersion = version
	}
}

// WithHeaders configures OTLP/gRPC connection headers.
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

// WithLogLevel configures the logging level for OpenTelemetry.
func WithLogLevel(loglevel string) Option {
	return func(c *Config) {
		c.LogLevel = loglevel
	}
}

// WithSpanExporterInsecure permits connecting to the
// trace endpoint without a certificate.
func WithSpanExporterInsecure(insecure bool) Option {
	return func(c *Config) {
		c.TracesExporterEndpointInsecure = insecure
	}
}

// WithMetricExporterInsecure permits connecting to the
// metric endpoint without a certificate.
func WithMetricExporterInsecure(insecure bool) Option {
	return func(c *Config) {
		c.MetricsExporterEndpointInsecure = insecure
	}
}

// WithResourceAttributes configures attributes on the resource; if the resource
// already exists, it sets additional attributes or overwrites those already there.
func WithResourceAttributes(attributes map[string]string) Option {
	return func(c *Config) {
		for k, v := range attributes {
			c.ResourceAttributes[k] = v
		}
	}
}

// WithPropagators configures propagators.
func WithPropagators(propagators []string) Option {
	return func(c *Config) {
		c.Propagators = propagators
	}
}

// Configures a global error handler to be used throughout an OpenTelemetry instrumented project.
// See "go.opentelemetry.io/otel".
func WithErrorHandler(handler otel.ErrorHandler) Option {
	return func(c *Config) {
		c.errorHandler = handler
	}
}

// WithMetricReportingPeriod configures the metric reporting period,
// how often the controller collects and exports metric data.
func WithMetricReportingPeriod(p time.Duration) Option {
	return func(c *Config) {
		c.MetricsReportingPeriod = fmt.Sprint(p)
	}
}

// WithMetricEnabled configures whether metrics should be enabled.
func WithMetricsEnabled(enabled bool) Option {
	return func(c *Config) {
		c.MetricsEnabled = enabled
	}
}

// WithTracesEnabled configures whether traces should be enabled.
func WithTracesEnabled(enabled bool) Option {
	return func(c *Config) {
		c.TracesEnabled = enabled
	}
}

// WithSpanProcessor adds one or more SpanProcessors.
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

type Protocol string

const (
	Protocol_GRPC          Protocol = "grpc"
	Protocol_HTTP_Protobuf Protocol = "http/protobuf"
	Protocol_HTTP_JSON     Protocol = "http/json"
)

func WithExporterProtocol(protocol Protocol) Option {
	return func(c *Config) {
		c.ExporterProtocol = string(protocol)
	}
}

func WithTracesExporterProtocol(protocol Protocol) Option {
	return func(c *Config) {
		c.TracesExporterProtocol = string(protocol)
	}
}

func WithMetricsExporterProtocol(protocol Protocol) Option {
	return func(c *Config) {
		c.MetricsExporterProtocol = string(protocol)
	}
}

// Logger is an interface for a logger that can be passed to WithLogger.
type Logger interface {
	Fatalf(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}

// WithLogger sets up the logger to be used by the launcher.
func WithLogger(logger Logger) Option {
	// In order to enable the environment parsing to send an error to the specified logger
	// we need to cache a copy of the logger in a package variable so that newConfig can use it
	// before we ever call the function returned by WithLogger. This is slightly messy, but
	// consistent with expected behavior of autoinstrumentation.
	defLogger = logger
	return func(c *Config) {
		c.Logger = logger
	}
}

type defaultLogger struct {
}

func (l *defaultLogger) Fatalf(format string, v ...interface{}) {
	//revive:disable:deep-exit needed for default logger
	log.Fatalf(format, v...)
}

func (l *defaultLogger) Debugf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

var defLogger Logger = &defaultLogger{}

type defaultHandler struct {
	logger Logger
}

func (l *defaultHandler) Handle(err error) {
	l.logger.Debugf("error: %v\n", err)
}

// Config is a configuration object; it is public so that it can be manipulated by vendors.
type Config struct {
	TracesExporterEndpoint          string   `env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,default=localhost:4317"`
	TracesExporterEndpointInsecure  bool     `env:"OTEL_EXPORTER_OTLP_TRACES_INSECURE,default=false"`
	TracesEnabled                   bool     `env:"OTEL_TRACES_ENABLED,default=true"`
	ServiceName                     string   `env:"OTEL_SERVICE_NAME"`
	ServiceVersion                  string   `env:"OTEL_SERVICE_VERSION,default=unknown"`
	MetricsExporterEndpoint         string   `env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT,default=localhost:4317"`
	MetricsExporterEndpointInsecure bool     `env:"OTEL_EXPORTER_OTLP_METRICS_INSECURE,default=false"`
	MetricsEnabled                  bool     `env:"OTEL_METRICS_ENABLED,default=true"`
	MetricsReportingPeriod          string   `env:"OTEL_EXPORTER_OTLP_METRICS_PERIOD,default=30s"`
	LogLevel                        string   `env:"OTEL_LOG_LEVEL,default=info"`
	Propagators                     []string `env:"OTEL_PROPAGATORS,default=tracecontext,baggage"`
	HeadersFromEnv                  string   `env:"OTEL_EXPORTER_OTLP_HEADERS"`
	ResourceAttributesFromEnv       string   `env:"OTEL_RESOURCE_ATTRIBUTES"`
	ExporterProtocol                string   `env:"OTEL_EXPORTER_OTLP_PROTOCOL,default=grpc"`
	TracesExporterProtocol          string   `env:"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"`
	MetricsExporterProtocol         string   `env:"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"`
	Headers                         map[string]string
	ResourceAttributes              map[string]string
	SpanProcessors                  []trace.SpanProcessor
	Resource                        *resource.Resource
	Logger                          Logger
	ShutdownFunctions               []func(c *Config) error
	errorHandler                    otel.ErrorHandler
}

func newConfig(opts ...Option) *Config {
	c := &Config{
		Headers:            map[string]string{},
		ResourceAttributes: map[string]string{},
		Logger:             defLogger,
		errorHandler:       &defaultHandler{logger: defLogger},
	}
	envError := envconfig.Process(context.Background(), c)
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

	c.Resource = newResource(c)
	return c
}

// Launcher is the object we're here for; it implements the initialization of Open Telemetry.
type Launcher struct {
	config        *Config
	shutdownFuncs []func() error
}

func newResource(c *Config) *resource.Resource {
	r := resource.Environment()

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

	// If a Traces-specific protocol wasn't specified, then use the generic one,
	// which has a default value.
	if c.TracesExporterProtocol == "" {
		c.TracesExporterProtocol = c.ExporterProtocol
	}

	return pipelines.NewTracePipeline(pipelines.PipelineConfig{
		Protocol:       c.TracesExporterProtocol,
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
	// If a Metrics-specific protocol wasn't specified, then use the generic one,
	// which has a default value.
	if c.MetricsExporterProtocol == "" {
		c.MetricsExporterProtocol = c.ExporterProtocol
	}

	return pipelines.NewMetricsPipeline(pipelines.PipelineConfig{
		Protocol:        c.MetricsExporterProtocol,
		Endpoint:        c.MetricsExporterEndpoint,
		Insecure:        c.MetricsExporterEndpointInsecure,
		Headers:         c.Headers,
		Resource:        c.Resource,
		ReportingPeriod: c.MetricsReportingPeriod,
	})
}

// ConfigureOpenTelemetry is a function that be called with zero or more options.
// Options can be the basic ones above, or provided by individual vendors.
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

// Shutdown is the function called to shut down OpenTelemetry. It invokes any registered
// shutdown functions.
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
