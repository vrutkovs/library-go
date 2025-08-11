/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dynamiclister

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

var _ Lister = &dynamicLister{}
var _ NamespaceLister = &dynamicNamespaceLister{}

// dynamicLister implements the Lister interface.
type dynamicLister struct {
	indexer cache.Indexer
	gvr     schema.GroupVersionResource
}

// New returns a new Lister.
func New(indexer cache.Indexer, gvr schema.GroupVersionResource) Lister {
	return &dynamicLister{indexer: indexer, gvr: gvr}
}

// List lists all resources in the indexer.
func (l *dynamicLister) List(ctx context.Context, selector labels.Selector) (ret []*unstructured.Unstructured, err error) {
	tracer := otel.GetTracerProvider().Tracer("library-go")
	ctx, span := tracer.Start(ctx, "dynamicLister.List", trace.WithAttributes(
		attribute.String("selector", selector.String()),
	))
	defer span.End()

	err = cache.ListAll(l.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*unstructured.Unstructured))
	})
	return ret, err
}

// Get retrieves a resource from the indexer with the given name
func (l *dynamicLister) Get(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	tracer := otel.GetTracerProvider().Tracer("library-go")
	ctx, span := tracer.Start(ctx, "dynamicNamespaceLister.Get", trace.WithAttributes(
		attribute.String("name", name),
	))
	defer span.End()

	obj, exists, err := l.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(l.gvr.GroupResource(), name)
	}
	return obj.(*unstructured.Unstructured), nil
}

// Namespace returns an object that can list and get resources from a given namespace.
func (l *dynamicLister) Namespace(ctx context.Context, namespace string) NamespaceLister {
	return &dynamicNamespaceLister{indexer: l.indexer, namespace: namespace, gvr: l.gvr}
}

// dynamicNamespaceLister implements the NamespaceLister interface.
type dynamicNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
	gvr       schema.GroupVersionResource
}

// List lists all resources in the indexer for a given namespace.
func (l *dynamicNamespaceLister) List(ctx context.Context, selector labels.Selector) (ret []*unstructured.Unstructured, err error) {
	tracer := otel.GetTracerProvider().Tracer("library-go")
	ctx, span := tracer.Start(ctx, "dynamicNamespaceLister.List", trace.WithAttributes(
		attribute.String("selector", selector.String()),
	))
	defer span.End()

	err = cache.ListAllByNamespace(l.indexer, l.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*unstructured.Unstructured))
	})
	return ret, err
}

// Get retrieves a resource from the indexer for a given namespace and name.
func (l *dynamicNamespaceLister) Get(name string) (*unstructured.Unstructured, error) {
	obj, exists, err := l.indexer.GetByKey(l.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(l.gvr.GroupResource(), name)
	}
	return obj.(*unstructured.Unstructured), nil
}
