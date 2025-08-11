package v1helpers

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func ObjToString(obj runtime.Object) string {
	if obj == nil {
		return "key"
	}
	pod, ok := obj.(*corev1.Pod)
	if ok {
		return fmt.Sprintf("pod %s/%s", pod.GetNamespace(), pod.GetName())
	}
	cm, ok := obj.(*corev1.ConfigMap)
	if ok {
		return fmt.Sprintf("configmap %s/%s", cm.GetNamespace(), cm.GetName())
	}
	secret, ok := obj.(*corev1.Secret)
	if ok {
		return fmt.Sprintf("secret %s/%s", secret.GetNamespace(), secret.GetName())
	}
	sa, ok := obj.(*corev1.ServiceAccount)
	if ok {
		return fmt.Sprintf("serviceaccount %s/%s", sa.GetNamespace(), sa.GetName())
	}
	node, ok := obj.(*corev1.Node)
	if ok {
		return fmt.Sprintf("node %s", node.GetName())
	}
	infra, ok := obj.(*configv1.Infrastructure)
	if ok {
		return fmt.Sprintf("infra %s", infra.GetName())
	}
	kapi, ok := obj.(*operatorv1.KubeAPIServer)
	if ok {
		return fmt.Sprintf("kubeapiserver %s", kapi.GetName())
	}
	clusterVersion, ok := obj.(*configv1.ClusterVersion)
	if ok {
		return fmt.Sprintf("clusterversion %s", clusterVersion.GetName())
	}
	clusterOperator, ok := obj.(*configv1.ClusterOperator)
	if ok {
		return fmt.Sprintf("clusteroperator %s", clusterOperator.GetName())
	}
	unstruct, ok := obj.(*unstructured.Unstructured)
	if ok {
		return fmt.Sprintf("%s/%s %s/%s", unstruct.GetObjectKind().GroupVersionKind().Group, unstruct.GetKind(), unstruct.GetNamespace(), unstruct.GetName())
	}
	return fmt.Sprintf("unknown: %#v", obj)
}
