package controllers

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openshift/library-go/pkg/operator/management"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"

	"go.opentelemetry.io/otel"
)

// preconditionsFulfilled a function that indicates whether all prerequisites are met and we can Sync.
type preconditionsFulfilled func(ctx context.Context) (bool, error)

// Provider abstracts external dependencies and preconditions that need to be dynamic during a downgrade/upgrade
type Provider interface {
	// EncryptedGRs returns resources that need to be encrypted
	EncryptedGRs() []schema.GroupResource

	// ShouldRunEncryptionControllers indicates whether external preconditions are satisfied so that encryption controllers can start synchronizing
	ShouldRunEncryptionControllers() (bool, error)
}

func shouldRunEncryptionController(ctx context.Context, operatorClient operatorv1helpers.OperatorClient, preconditionsFulfilledFn preconditionsFulfilled, shouldRunFn func() (bool, error)) (bool, error) {
	tracer := otel.GetTracerProvider().Tracer("library-go")
	ctx, span := tracer.Start(ctx, "encryption.shouldRunEncryptionController")
	defer span.End()

	if shouldRun, err := shouldRunFn(); !shouldRun || err != nil {
		return false, err
	}

	operatorSpec, _, _, err := operatorClient.GetOperatorState(ctx)
	if err != nil {
		return false, err
	}

	if !management.IsOperatorManaged(ctx, operatorSpec.ManagementState) {
		return false, nil
	}

	return preconditionsFulfilledFn(ctx)
}
