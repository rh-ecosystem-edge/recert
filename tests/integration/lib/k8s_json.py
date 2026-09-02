#!/usr/bin/env python3
"""Helpers for integration-test Kubernetes JSON.

complete: fill empty maps/arrays required by recert's prost-generated serde
(no #[serde(default)]). Recert protobuf-encodes edited Secret/Deployment/ConfigMap
values on commit_to_actual_etcd regardless of the original JSON encoding.

tls-secret: emit a completed kubernetes.io/tls Secret JSON document.
extract-tls: pull tls.crt/tls.key PEM from JSON or protobuf etcd bytes.
"""
import base64
import json
import re
import sys

OBJECT_META = {
    "labels": {},
    "annotations": {},
    "ownerReferences": [],
    "finalizers": [],
    "managedFields": [],
}

LABEL_SELECTOR = {
    "matchLabels": {},
    "matchExpressions": [],
}

POD_SPEC = {
    "volumes": [],
    "initContainers": [],
    "containers": [],
    "ephemeralContainers": [],
    "nodeSelector": {},
    "imagePullSecrets": [],
    "tolerations": [],
    "hostAliases": [],
    "readinessGates": [],
    "overhead": {},
    "topologySpreadConstraints": [],
    "schedulingGates": [],
    "resourceClaims": [],
}

CONTAINER = {
    "command": [],
    "args": [],
    "ports": [],
    "envFrom": [],
    "env": [],
    "resizePolicy": [],
    "volumeMounts": [],
    "volumeDevices": [],
}

SECRET = {
    "data": {},
    "stringData": {},
}

CONFIG_MAP = {
    "data": {},
    "binaryData": {},
}


def fill(dst, defaults):
    for key, value in defaults.items():
        if key not in dst or dst[key] is None:
            dst[key] = json.loads(json.dumps(value))
    return dst


def complete_metadata(meta):
    if not isinstance(meta, dict):
        meta = {}
    return fill(meta, OBJECT_META)


def complete_container(container):
    fill(container, CONTAINER)
    return container


def complete_pod_spec(spec):
    fill(spec, POD_SPEC)
    for container in spec.get("containers") or []:
        complete_container(container)
    for container in spec.get("initContainers") or []:
        complete_container(container)
    return spec


def complete(obj):
    kind = obj.get("kind")
    if "metadata" in obj or kind in ("Secret", "Deployment", "ConfigMap"):
        obj["metadata"] = complete_metadata(obj.get("metadata") or {})
    if kind == "Secret":
        fill(obj, SECRET)
    elif kind == "ConfigMap":
        fill(obj, CONFIG_MAP)
    elif kind == "Deployment":
        spec = obj.setdefault("spec", {})
        selector = spec.get("selector") or {}
        fill(selector, LABEL_SELECTOR)
        spec["selector"] = selector
        template = spec.setdefault("template", {})
        template["metadata"] = complete_metadata(template.get("metadata") or {})
        template["spec"] = complete_pod_spec(template.get("spec") or {})
        spec["template"] = template
    return obj


def tls_secret(ns, name, cert_path, key_path):
    return complete({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": ns},
        "type": "kubernetes.io/tls",
        "data": {
            "tls.crt": list(open(cert_path, "rb").read()),
            "tls.key": list(open(key_path, "rb").read()),
        },
    })


def _pem_from_json(data, field):
    value = data["data"][field]
    if isinstance(value, list):
        return bytes(value)
    if isinstance(value, str):
        return base64.b64decode(value)
    raise SystemExit(f"unexpected tls field type: {type(value)}")


def _pem_from_protobuf(raw, field):
    if field == "tls.crt":
        match = re.search(br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.S)
    else:
        match = re.search(br"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", raw, re.S)
    if not match:
        raise SystemExit(f"could not extract {field} from etcd protobuf value")
    return match.group(0) + b"\n"


def extract_tls_pems(raw):
    stripped = raw.lstrip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        data = json.loads(raw)
        return _pem_from_json(data, "tls.crt"), _pem_from_json(data, "tls.key")
    return _pem_from_protobuf(raw, "tls.crt"), _pem_from_protobuf(raw, "tls.key")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "complete"
    if cmd == "complete":
        json.dump(complete(json.load(sys.stdin)), sys.stdout, separators=(",", ":"))
        return
    if cmd == "tls-secret":
        ns, name, cert_path, key_path = sys.argv[2:6]
        json.dump(tls_secret(ns, name, cert_path, key_path), sys.stdout, separators=(",", ":"))
        return
    if cmd == "extract-tls":
        cert_path, key_path = sys.argv[2:4]
        cert, key = extract_tls_pems(sys.stdin.buffer.read())
        open(cert_path, "wb").write(cert)
        open(key_path, "wb").write(key)
        return
    raise SystemExit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
