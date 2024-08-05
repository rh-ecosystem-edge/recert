package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	OPENSHIFT_APISERVER_DEPLOYMENT_YAML_URL = "https://raw.githubusercontent.com/openshift/cluster-openshift-apiserver-operator/release-4.16/bindata/v3.11.0/openshift-apiserver/deploy.yaml"

	OPENSHIFT_OAUTH_APISERVER_DEPLOYMENT_YAML_URL = "https://raw.githubusercontent.com/openshift/cluster-authentication-operator/release-4.16/bindata/oauth-apiserver/deploy.yaml"

	OPENSHIFT_APISERVER_JSON_FILEPATH = "../../src/bindata/openshift-apiserver-deployment.json"

	OPENSHIFT_OAUTH_APISERVER_JSON_FILEPATH = "../../src/bindata/openshift-oauth-apiserver-deployment.json"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func apiServerDeploymentJSON() {
	fmt.Println("Fetching OpenShift APIServer deployment YAML...")

	resp, err := http.Get(OPENSHIFT_APISERVER_DEPLOYMENT_YAML_URL)
	check(err)

	apiServerDeployment, err := io.ReadAll(resp.Body)
	check(err)

	required := resourceread.ReadDeploymentV1OrDie(apiServerDeployment)

	if required.Spec.Template.Annotations == nil {
		required.Spec.Template.Annotations = map[string]string{}
	}
	annotations := map[string]string{
		"operator.openshift.io/dep-desired.generation":                              "${DESIRED_GENERATION}",
		"operator.openshift.io/dep-openshift-apiserver.config.configmap":            "${CONFIG_HASH}",
		"operator.openshift.io/dep-openshift-apiserver.etcd-client.secret":          "${ETCD_CLIENT_HASH}",
		"operator.openshift.io/dep-openshift-apiserver.etcd-serving-ca.configmap":   "${ETCD_SERVING_CA_HASH}",
		"operator.openshift.io/dep-openshift-apiserver.image-import-ca.configmap":   "${IMAGE_IMPORT_CA_HASH}",
		"operator.openshift.io/dep-openshift-apiserver.trusted-ca-bundle.configmap": "${TRUSTED_CA_BUNDLE_HASH}",
	}
	for k, v := range annotations {
		required.Spec.Template.Annotations[k] = v
	}
	replicas := int32(1)
	required.Spec.Replicas = &replicas
	required.Spec.Template.ObjectMeta.Labels["openshift-apiserver-anti-affinity"] = "true"
	required.Spec.Template.ObjectMeta.Labels["revision"] = "${REVISION}"
	required.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0].LabelSelector.MatchLabels["openshift-apiserver-anti-affinity"] = "true"

	proxyEnvVars := []v1.EnvVar{
		{Name: "HTTPS_PROXY", Value: "${HTTPS_PROXY}"},
		{Name: "HTTP_PROXY", Value:"${HTTP_PROXY}"},
		{Name: "NO_PROXY", Value:"${NO_PROXY}"},
	}
	for i, container := range required.Spec.Template.Spec.Containers {
			required.Spec.Template.Spec.Containers[i].Env = append(container.Env, proxyEnvVars...)
	}

	jsonBytes, err := json.Marshal(required.Spec)
	check(err)

	err = os.WriteFile(OPENSHIFT_APISERVER_JSON_FILEPATH, jsonBytes, 0o644)
	check(err)

	fmt.Println("Writing file to ", OPENSHIFT_APISERVER_JSON_FILEPATH)
}

func oauthAPIServerDeploymentJSON() {
	fmt.Println("Fetching OpenShift OAuth APIServer deployment YAML...")

	resp, err := http.Get(OPENSHIFT_OAUTH_APISERVER_DEPLOYMENT_YAML_URL)
	check(err)

	apiServerDeployment, err := io.ReadAll(resp.Body)
	check(err)

	required := resourceread.ReadDeploymentV1OrDie(apiServerDeployment)

	if required.Spec.Template.Annotations == nil {
		required.Spec.Template.Annotations = map[string]string{}
	}
	annotations := map[string]string{
		"operator.openshift.io/dep-openshift-oauth-apiserver.etcd-client.secret":        "${ETCD_CLIENT_HASH}",
		"operator.openshift.io/dep-openshift-oauth-apiserver.etcd-serving-ca.configmap": "${ETCD_SERVING_CA_HASH}",
	}
	for k, v := range annotations {
		required.Spec.Template.Annotations[k] = v
	}
	replicas := int32(1)
	required.Spec.Replicas = &replicas
	required.Spec.Template.ObjectMeta.Labels["oauth-apiserver-anti-affinity"] = "true"
	required.Spec.Template.ObjectMeta.Labels["revision"] = "${REVISION}"
	required.Spec.Template.Spec.Affinity = &v1.Affinity{
		PodAntiAffinity: &v1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []v1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"apiserver":                     "true",
							"app":                           "openshift-oauth-apiserver",
							"oauth-apiserver-anti-affinity": "true",
						},
					},
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		},
	}

	jsonBytes, err := json.Marshal(required.Spec)
	check(err)

	err = os.WriteFile(OPENSHIFT_OAUTH_APISERVER_JSON_FILEPATH, jsonBytes, 0o644)
	check(err)

	fmt.Println("Writing file to ", OPENSHIFT_OAUTH_APISERVER_JSON_FILEPATH)
}

func main() {
	apiServerDeploymentJSON()
	oauthAPIServerDeploymentJSON()
}
