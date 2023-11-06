# Get all resources of the given kind from the recert summary
def recertKind(kind):
    [
        # Recurse through the summary, taking anything that has "locations"
        .. | .locations? | select(. != null)
        # Ignore filesystem locations because they're not recorded in the ownership file 
        | .k8s[]
        # Ignore the k8s: prefix, ignore the location inside the YAML - we just want the kind, namespace and name
        | split(" ")[1] 
        # Only take the secrets
        | split("/") | select(.[0] == kind)[1]
    ]
    | sort | unique[]
    | split(":") | {"Namespace": .[0], "Name": .[1]};

# Get all resources of the given kind from the ownership file
def ownershipKind(kind):
    if kind == "Secret" then
        [.certKeyPairs[].secretLocation]
        | sort_by("\(.Namespace)/\(.Name)")[]
    else
        [.certificateAuthorityBundles[].configMapLocation]
        | sort_by("\(.Namespace)/\(.Name)")[]
    end;

# Name our input parameters
. as $root 
| $root[0] as $recert 
| $root[1] as $ownership 

# Get the secrets and configmaps from the recert summary
| [ $recert | recertKind("Secret")] as $recert_secrets
| [ $recert | recertKind("ConfigMap")] as $recert_configmaps

# Get the secrets and configmaps from the recert summary
| [ $ownership | ownershipKind("Secret")] as $ownership_secrets
| [ $ownership | ownershipKind("ConfigMap")] as $ownership_configmaps

# Check missing
| [$ownership_secrets[] | select($recert_secrets | contains(.) | not)] as $missing_secrets
| [$ownership_configmaps[] | select($recert_configmaps | contains(.) | not)] as $missing_configmaps

# Print
| {
    "MissingSecrets": $missing_secrets,
    "MissingConfigMaps": $missing_configmaps
}



