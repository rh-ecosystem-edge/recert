# Configmaps
- [x] `kubernetes.io/configmaps/kube-system/cluster-config-v1.yaml`
- [x] `kubernetes.io/configmaps/openshift-apiserver/config.yaml`
- [x] `kubernetes.io/configmaps/openshift-authentication/v4-0-config-system-cliconfig.yaml`
- [x] `kubernetes.io/configmaps/openshift-authentication/v4-0-config-system-metadata.yaml`
- [x] `kubernetes.io/configmaps/openshift-config-managed/console-public.yaml`
- [x] `kubernetes.io/configmaps/openshift-config-managed/monitoring-shared-config.yaml`
- [x] `kubernetes.io/configmaps/openshift-config-managed/oauth-openshift.yaml`
- [x] `kubernetes.io/configmaps/openshift-console/console-config.yaml`
- [x] `kubernetes.io/configmaps/openshift-etcd/cluster-config-v1.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-apiserver/config-3.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-apiserver/config-4.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-apiserver/config-5.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-apiserver/config-6.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-apiserver/config-7.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-apiserver/config.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-apiserver/oauth-metadata-6.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-apiserver/oauth-metadata-7.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-apiserver/oauth-metadata.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/config-10.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/config-11.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/config-7.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/config-8.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/config-9.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/config.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/controller-manager-kubeconfig-10.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/controller-manager-kubeconfig-11.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/controller-manager-kubeconfig-7.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/controller-manager-kubeconfig-8.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/controller-manager-kubeconfig-9.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/controller-manager-kubeconfig.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/kube-controller-manager-pod-10.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/kube-controller-manager-pod-11.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/kube-controller-manager-pod-7.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/kube-controller-manager-pod-8.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/kube-controller-manager-pod-9.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-controller-manager/kube-controller-manager-pod.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-scheduler/scheduler-kubeconfig-2.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-scheduler/scheduler-kubeconfig-3.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-scheduler/scheduler-kubeconfig-4.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-scheduler/scheduler-kubeconfig-5.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-scheduler/scheduler-kubeconfig-6.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-scheduler/scheduler-kubeconfig-7.yaml`
- [x] `kubernetes.io/configmaps/openshift-kube-scheduler/scheduler-kubeconfig.yaml`
- [x] `kubernetes.io/configmaps/openshift-ovn-kubernetes/ovnkube-config.yaml`

# config.openshift.io
- [x] `kubernetes.io/config.openshift.io/consoles/cluster.yaml`
- [x] `kubernetes.io/config.openshift.io/dnses/cluster.yaml`
- [x] `kubernetes.io/config.openshift.io/infrastructures/cluster.yaml`
- [x] `kubernetes.io/config.openshift.io/ingresses/cluster.yaml`

# console.openshift.io
- [x] `kubernetes.io/console.openshift.io/consoleclidownloads/oc-cli-downloads.yaml`

# controllerrevisions

We can just delete those

- [x] `kubernetes.io/controllerrevisions/openshift-machine-config-operator/machine-config-server-6d95948b4d.yaml`
- [x] `kubernetes.io/controllerrevisions/openshift-monitoring/alertmanager-main-649bdff49.yaml`
- [x] `kubernetes.io/controllerrevisions/openshift-monitoring/prometheus-k8s-5bfb4fc75b.yaml`
- [x] `kubernetes.io/controllerrevisions/openshift-multus/multus-additional-cni-plugins-795fb9cf6b.yaml`
- [x] `kubernetes.io/controllerrevisions/openshift-multus/multus-b8885bc5b.yaml`
- [x] `kubernetes.io/controllerrevisions/openshift-ovn-kubernetes/ovnkube-node-667b89c65f.yaml`

# controlplane.operator.openshift.io

We can just delete those

- [x] `kubernetes.io/controlplane.operator.openshift.io/podnetworkconnectivitychecks/openshift-network-diagnostics/network-check-source-master1-to-load-balancer-api-external.yaml`
- [x] `kubernetes.io/controlplane.operator.openshift.io/podnetworkconnectivitychecks/openshift-network-diagnostics/network-check-source-master1-to-load-balancer-api-internal.yaml`

# daemonsets

We should just let it reconcile ?

- [ ] `kubernetes.io/daemonsets/openshift-machine-config-operator/machine-config-server.yaml`
- [ ] `kubernetes.io/daemonsets/openshift-multus/multus-additional-cni-plugins.yaml`
- [ ] `kubernetes.io/daemonsets/openshift-multus/multus.yaml`
- [ ] `kubernetes.io/daemonsets/openshift-ovn-kubernetes/ovnkube-node.yaml`

# deployments
- [ ] `kubernetes.io/deployments/openshift-cluster-version/cluster-version-operator.yaml`
- [ ] `kubernetes.io/deployments/openshift-ingress/router-default.yaml`

# machineconfiguration.openshift.io
- [x] `kubernetes.io/machineconfiguration.openshift.io/controllerconfigs/machine-config-controller.yaml`
- [x] `kubernetes.io/machineconfiguration.openshift.io/machineconfigs/00-master.yaml`
- [x] `kubernetes.io/machineconfiguration.openshift.io/machineconfigs/rendered-master-5d64e3ee82405c9295efd994b0b5770a.yaml`
- [x] `kubernetes.io/machineconfiguration.openshift.io/machineconfigs/rendered-master-e3add8c769db72621a4d3591d59f440f.yaml`

# monitoring.coreos.com
- [ ] `kubernetes.io/monitoring.coreos.com/alertmanagers/openshift-monitoring/main.yaml`
- [ ] `kubernetes.io/monitoring.coreos.com/prometheuses/openshift-monitoring/k8s.yaml`

# operator.openshift.io

Automatically reconciled by CVO

- [ ] `kubernetes.io/operator.openshift.io/authentications/cluster.yaml`
- [ ] `kubernetes.io/operator.openshift.io/ingresscontrollers/openshift-ingress-operator/default.yaml`
- [ ] `kubernetes.io/operator.openshift.io/kubeapiservers/cluster.yaml`
- [ ] `kubernetes.io/operator.openshift.io/kubecontrollermanagers/cluster.yaml`
- [ ] `kubernetes.io/operator.openshift.io/openshiftapiservers/cluster.yaml`

# pods
- [ ] `kubernetes.io/pods/openshift-cluster-version/cluster-version-operator-68c864cbb4-27mn4.yaml`
- [ ] `kubernetes.io/pods/openshift-ingress/router-default-775775c67f-24zql.yaml`
- [ ] `kubernetes.io/pods/openshift-kube-controller-manager/kube-controller-manager-master1.yaml`
- [ ] `kubernetes.io/pods/openshift-machine-config-operator/machine-config-server-lvsjf.yaml`
- [ ] `kubernetes.io/pods/openshift-monitoring/alertmanager-main-0.yaml`
- [ ] `kubernetes.io/pods/openshift-monitoring/prometheus-k8s-0.yaml`
- [ ] `kubernetes.io/pods/openshift-multus/multus-additional-cni-plugins-8r4mp.yaml`
- [ ] `kubernetes.io/pods/openshift-multus/multus-r92bd.yaml`
- [ ] `kubernetes.io/pods/openshift-ovn-kubernetes/ovnkube-node-sxqrk.yaml`

# replicasets
- [ ] `kubernetes.io/replicasets/openshift-cluster-version/cluster-version-operator-68c864cbb4.yaml`
- [ ] `kubernetes.io/replicasets/openshift-ingress/router-default-775775c67f.yaml`

# secrets
- [x] `kubernetes.io/secrets/openshift-authentication/v4-0-config-system-router-certs.yaml`
- [x] `kubernetes.io/secrets/openshift-config-managed/router-certs.yaml`
- [x] `kubernetes.io/secrets/openshift-kube-apiserver/external-loadbalancer-serving-certkey.yaml`
- [x] `kubernetes.io/secrets/openshift-kube-apiserver/internal-loadbalancer-serving-certkey.yaml`
- [ ] `kubernetes.io/secrets/openshift-kube-apiserver/node-kubeconfigs.yaml`
- [ ] `kubernetes.io/secrets/openshift-machine-api/master-user-data-managed.yaml`
- [ ] `kubernetes.io/secrets/openshift-machine-api/master-user-data.yaml`
- [ ] `kubernetes.io/secrets/openshift-machine-api/worker-user-data-managed.yaml`
- [ ] `kubernetes.io/secrets/openshift-machine-api/worker-user-data.yaml`

# statefulsets
- [ ] `kubernetes.io/statefulsets/openshift-monitoring/alertmanager-main.yaml`
- [ ] `kubernetes.io/statefulsets/openshift-monitoring/prometheus-k8s.yaml`

# oauth
- [ ] `openshift.io/oauth/clients/console.yaml`
- [ ] `openshift.io/oauth/clients/openshift-browser-client.yaml`
- [ ] `openshift.io/oauth/clients/openshift-challenging-client.yaml`

# routes
- [ ] `openshift.io/routes/openshift-authentication/oauth-openshift.yaml`
- [ ] `openshift.io/routes/openshift-console/console.yaml`
- [ ] `openshift.io/routes/openshift-console/downloads.yaml`
- [ ] `openshift.io/routes/openshift-ingress-canary/canary.yaml`
- [ ] `openshift.io/routes/openshift-monitoring/alertmanager-main.yaml`
- [ ] `openshift.io/routes/openshift-monitoring/prometheus-k8s-federate.yaml`
- [ ] `openshift.io/routes/openshift-monitoring/prometheus-k8s.yaml`
- [ ] `openshift.io/routes/openshift-monitoring/thanos-querier.yaml`
