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

package otelgrpc

import (
	"context"

	"google.golang.org/grpc/metadata"

	"go.opentelemetry.io/otel/api/baggage"
	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/api/propagation"
	"go.opentelemetry.io/otel/api/trace"
	"go.opentelemetry.io/otel/label"
)

// instrumentationName is the name of this instrumentation package.
const instrumentationName = "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"

// config is a group of options for this instrumentation.
type config struct {
	Propagators    propagation.Propagators
	TracerProvider trace.TracerProvider
}

// Option applies an option value for a config.
type Option interface {
	Apply(*config)
}

// newConfig returns a config configured with all the passed Options.
func newConfig(opts []Option) *config {
	c := &config{
		Propagators:    global.Propagators(),
		TracerProvider: global.TracerProvider(),
	}
	for _, o := range opts {
		o.Apply(c)
	}
	return c
}

type propagatorsOption struct{ p propagation.Propagators }

func (o propagatorsOption) Apply(c *config) {
	c.Propagators = o.p
}

// WithPropagators returns an Option to use the Propagators when extracting
// and injecting trace context from requests.
func WithPropagators(p propagation.Propagators) Option {
	return propagatorsOption{p: p}
}

type tracerProviderOption struct{ tp trace.TracerProvider }

func (o tracerProviderOption) Apply(c *config) {
	c.TracerProvider = o.tp
}

// WithTracerProvider returns an Option to use the TracerProvider when
// creating a Tracer.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return tracerProviderOption{tp: tp}
}

type metadataSupplier struct {
	metadata *metadata.MD
}

func (s *metadataSupplier) Get(key string) string {
	values := s.metadata.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (s *metadataSupplier) Set(key string, value string) {
	s.metadata.Set(key, value)
}

// Inject injects correlation context and span context into the gRPC
// metadata object. This function is meant to be used on outgoing
// requests.
func Inject(ctx context.Context, metadata *metadata.MD, opts ...Option) {
	c := newConfig(opts)
	propagation.InjectHTTP(ctx, c.Propagators, &metadataSupplier{
		metadata: metadata,
	})
}

// Extract returns the correlation context and span context that
// another service encoded in the gRPC metadata object with Inject.
// This function is meant to be used on incoming requests.
func Extract(ctx context.Context, metadata *metadata.MD, opts ...Option) ([]label.KeyValue, trace.SpanContext) {
	c := newConfig(opts)
	ctx = propagation.ExtractHTTP(ctx, c.Propagators, &metadataSupplier{
		metadata: metadata,
	})

	spanContext := trace.RemoteSpanContextFromContext(ctx)
	var correlationCtxLabels []label.KeyValue
	baggage.MapFromContext(ctx).Foreach(func(l label.KeyValue) bool {
		correlationCtxLabels = append(correlationCtxLabels, l)
		return true
	})

	return correlationCtxLabels, spanContext
}
