# RPM lock files in Konflux

## Overview
When installing external software via RPMs in Konflux builds, we need to integrate a RPM lock file management in our workflow: the primary goal is to ensure that hermetic builds, required by Konflux Conforma, can pre-fetch RPM dependencies before building the Docker image. A hermetic build without lock files, relying on dynamic downloads exclusively, would fail due to no internet access otherwise.

More information about the hermetic builds in the [Konflux Hermetic Builds FAQ](https://konflux.pages.redhat.com/docs/users/faq/hermetic.html)

## RPM lock file management

### Generate a rpm lock file

We will be using a generator named `rpm-lock-file-prototype` according to the directions provided by that project in the [rpm-lockfile-prototype README](https://github.com/konflux-ci/rpm-lockfile-prototype?tab=readme-ov-file#installation) to generate the `rpms.lock.yaml`.

The recert image has a build stage and final runtime stage which requires different rpms to be installed.To that end, we have encapsulated the `rpms.in.yaml` and the resolved `rpms.lock.yaml` under two specific dirs which correspond to the specific stage: `lock-build` and `lock-runtime`.

The `rpms.lock.yaml` has been generated from the input provided by `rpms.in.yaml`: this file must be manually created from scratch by Konflux developers with the following fields:

1. `repofiles`: the .repo file extracted from the runtime base image for recert (a `redhat.repo` file from rhel9 so far)
2. `packages`: the rpms we depend on
3. `arches`: the supported architectures for building
4. `Containerfile`: the Containerfile used to build the recert image.

### Introduce rpms based on new subscriptions

A subscription-manager/activation-key config has been carried out to fetch RPMs.See how to activate subscriptions in the   [Konflux activation key doc](https://konflux.pages.redhat.com/docs/users/how-tos/configuring/activation-keys-subscription.html#_configuring_an_rpm_lockfile_for_hermetic_builds).

### Configure the .tekton yaml files

The push/pull tekton yaml files in `.tekton` have been configured to setup a hermetic build workflow according to the [Konflux prefetch doc](https://konflux.pages.redhat.com/docs/users/how-tos/configuring/prefetching-dependencies.html#_procedure)

1. Enable hermetic builds
```yaml
   - name: hermetic
     value: "true"
```
2. Enable rpm pre-fetch per stage, configuring two directories 
```yaml
   - name: prefetch-input
     value: '[{"type": "rpm", "path": ".konflux/lock-build"}, {"type": "rpm", "path": ".konflux/lock-runtime"}]'
```

3. Enable dev package managers
```yaml
   - name: dev-package-managers
     value: "true"
```

### Update  rpms
Konflux provides a mechanism (Mintmaker) to automatically file PRs to update RPM versions and generate the updated lockfile. At time of writing, this is limited to a `rpm.locks.yaml` file present in the project root.
