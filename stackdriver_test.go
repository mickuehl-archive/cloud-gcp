package gcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/smallstep/assert"
	"github.com/stretchr/testify/require"

	"github.com/txsvc/stdlib/observer"
	"github.com/txsvc/stdlib/pkg/env"
	"github.com/txsvc/stdlib/pkg/provider"
)

func TestGoogleSetup(t *testing.T) {
	require.True(t, env.Exists("PROJECT_ID"))
	require.True(t, env.Exists("GOOGLE_APPLICATION_CREDENTIALS"))
}

func TestLoggingImpl(t *testing.T) {
	loggingImpl := provider.WithProvider("google.cloud.logging", observer.TypeLogger, NewGoogleStackdriverProvider)
	assert.NotNil(t, loggingImpl)

	prov, err := observer.NewConfig(loggingImpl)
	assert.NotNil(t, prov)
	assert.NoError(t, err)

	observer.Log("TestLoggingImpl")
}

func TestErrorReportingImpl(t *testing.T) {
	errorConfig := provider.WithProvider("google.cloud.error", observer.TypeErrorReporter, NewGoogleStackdriverProvider)
	assert.NotNil(t, errorConfig)

	prov, err := observer.NewConfig(errorConfig)
	assert.NotNil(t, prov)
	assert.NoError(t, err)

	e := fmt.Errorf("TestLoggingImpl")
	observer.ReportError(e)
}

func TestMetricsImpl(t *testing.T) {
	metricsConfig := provider.WithProvider("google.cloud.metrics", observer.TypeMetrics, NewGoogleStackdriverProvider)
	assert.NotNil(t, metricsConfig)

	prov, err := observer.NewConfig(metricsConfig)
	assert.NotNil(t, prov)
	assert.NoError(t, err)

	observer.Meter(context.TODO(), "TestMetricsImpl", "k1", "v1", "k2", "v2")
}
