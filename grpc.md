# Why `e2e-aws-ovn-single-node-recert-parallel` keeps failing

Job: `pull-ci-rh-ecosystem-edge-recert-{main,release-4.22,release-5.0}-e2e-aws-ovn-single-node-recert-parallel`

## TL;DR

- One test is what fails the job:
  `[sig-network-edge][Conformance][Area:Networking][Feature:Router] The HAProxy router should pass the gRPC interoperability tests`.
  Two other tests fail in every run (a cluster-config-operator restart-count check and an `oc` RHEL8/9 binary-extract
  test), but they are only informing and don't fail the job. The last passing run had both of them failing too.
- It's **not a recert bug and not an SNO bug**. The best explanation is a DNS race between the test and the
  brand-new hostname it creates. Only this job's network setup turns losing that race into a long outage: the test
  runner reaches the cluster through a proxy on a bastion VM.
- The same pattern used to break the http2 router test in this job (100% failure). It was fixed by making that test
  wait for DNS before its first request. The gRPC test never got that fix.

## Who's who

| Actor | What it is |
|---|---|
| **Test runner** | The `openshift-tests` binary, running in a CI pod on the CI build cluster (outside AWS). Acts as the "outside client". |
| **The cluster** | The SNO cluster the job installs in AWS (and then recerts). |
| **Router** | OpenShift's built-in HAProxy. Takes outside HTTP traffic for `*.apps.<cluster>` and sends it to apps according to `Route` objects. |
| **Shard** | An extra, private router a test creates just for itself (an additional `IngressController`). It serves its own hostname suffix `*.<test-ns>.apps.<cluster>` and gets its own router pod, its own AWS load balancer (ELB) and its own Route53 DNS record. |
| **Bastion + Squid** | An extra VM this job's workflow puts in the cluster's AWS VPC. It runs Squid, an HTTP proxy. The workflow sets `HTTP_PROXY`/`HTTPS_PROXY` (with `NO_PROXY=localhost,127.0.0.1`), so **all** test-runner traffic to the cluster goes through Squid. Squid resolves hostnames via the VPC's AWS DNS resolver. Plain SNO jobs (`openshift-e2e-aws-single-node`) have no bastion and no proxy. |

Workflow: `openshift-e2e-aws-single-node-recert` (shared VPC, bastion, custom security groups, `proxy-config-generate`,
min-permission IAM user, install, `single-node-recert`, `single-node-e2e-test`).

## What the gRPC test does

Source: `openshift/origin` `test/extended/router/grpc-interop.go`

```
1. start a gRPC server pod (ingress-operator serve-grpc-test-server; h2c :1110, TLS :8443)
2. create 4 Routes to it: h2c (plain), edge, reencrypt, passthrough
3. create a shard and wait for Admitted / Available / LoadBalancerManaged / LoadBalancerReady
   -- it does NOT wait for DNS
4. from the test runner, dial grpc-interop-h2c.<ns>.apps.<cluster>:80

   test runner ──► Squid (bastion) ──► VPC DNS lookup
                                    └─► ELB ──► shard router ──► gRPC server pod

5. run 13 gRPC interop cases through each of the 4 routes (5 min retry poll per case)
```

## What fails

Step 4. The first `grpc.Dial` never completes. `grpc-interop/clientconn.go:47` calls
`grpc.Dial(..., grpc.WithBlock())` with no deadline. The `wait.PollImmediate(..., 5*time.Minute, ...)` around it only
checks its deadline between attempts, so a dial that never returns hangs the test until openshift-tests kills it
at 15 minutes ("Interrupted by User").

The progress report at the interrupt confirms this. The goroutine had sat in `grpc.(*ClientConn).WaitForStateChange`
under `grpc.DialContext` for 14 minutes.

In the failing run we have full artifacts for (release-4.22 build `2107492608283512832`), everything on the cluster
side was fine:

- 21:37:44 shard created. Cloud controller creates the ELB and its security group, and adds the
  ELB→node security-group rule and the instance.
- 21:37:48 ingress-operator publishes `*.e2e-test-grpc-interop-xvhcr.apps...` CNAME → ELB to both Route53 zones.
- 21:38:20 shard router has loaded the routes; gRPC server pod is up ("Serving h2c at :1110").
- 21:38:21 test logs `Dialling ... grpc-interop-h2c...:80`, then nothing else until the 21:52:36 interrupt.

The same hang shows up in every failing run checked (June 10, June 17, July 20, Sept 18, Oct 6).

## Why (best explanation)

The test dials ~30s after the DNS record is created. That's apparently too early for Squid's lookup through the
VPC resolver.

**Hypothesis, not directly observed:** the VPC resolver answers "no such name" and caches that for the Route53
hosted zone's negative TTL (AWS default SOA → 900s = 15 min). That's longer than the test's window, so every
gRPC reconnect hits the cached answer. Normal jobs resolve through the CI cluster's own DNS (OpenShift CoreDNS
caches negative answers for a short time), so an early miss costs seconds, not minutes.

## Evidence

### 1. Not SNO, not AWS in general (Sippy)

| Release | Topology:single | Platform:aws | All |
|---|---|---|---|
| 4.22 | 96/96 pass | 379/379 | 749/750 |
| 5.0 | 79/81 pass | 506/508 | 1295/1297 |

### 2. The http2 router test hit the same thing, and a DNS wait fixed it

The http2 test (`test/extended/router/http2.go`) follows the same pattern: create a shard, then send requests from
the test runner right away. Origin commit `0c13a1b511` (2026-07-06, "wait for DNS before running http2 tests")
added `resolveHost(...)` before the first request (`http2.go:488`). It's on main/release-5.0 but **not** on
release-4.22.

| Branch | Has DNS wait? | http2 test failures in this job |
|---|---|---|
| main, June (before fix) | no | **30/30 runs** |
| main, after fix | yes | 4/151 |
| release-4.22 | no | **22/22 runs** |
| release-5.0 | yes | 0/17 |

On release-4.22 the http2 failure is 602 consecutive `Service Unavailable` errors over 5 minutes. That's how Go
reports Squid refusing the CONNECT, not a response from the router.

### 3. The last passing run had the same setup

Build `2083819206008115200` (PR #1855, 2026-08-02, 5.0 payload):

- Same steps: bastion, proxy, shared VPC, custom SGs, recert.
- `HTTP_PROXY` was in use.
- gRPC test **passed** (166s).
- The job passed even though cluster-config-operator, oc-extract and one API LB test failed. Those are informing.

So the topology alone doesn't guarantee failure. It's a race.

### 4. Timeline: flaky, then always failing (all branches at once)

gRPC test results across runs that reached e2e:

| Period | main | release-4.22 |
|---|---|---|
| June | failed 9/30 | failed 2/4 |
| July 1–15 | failed 1/6 | failed 0/2 |
| July 16–31 | failed 24/28 | failed 3/4 |
| Aug 3 onward | failed every run (115) | failed every run |

Last passes on main: 2026-07-10 (#1758), 07-14 and 07-15 (#1757), 07-21 and 07-27 (#1829), 08-02 (#1855).

### 5. Things ruled out

- **recert:** passes happened on recert'd clusters. The flakiness predates any recent recert change. Recert
  only regenerates certs, reusing the existing signer keys, and doesn't touch DNS or ELBs. The h2c route doesn't
  even use TLS. PR content doesn't decide it either: #1829 has both passes and failures in the same week.
- **grpc-go bump** (v1.75.1 → v1.81.1 on origin main, 2026-07-25): release-4.22 still has v1.75.1 and fails the same way.
- **Workflow / recert step changes:** the workflow last changed 2026-04-17 and the recert step script 2026-02-16.
  No step-registry change near July 20 stands out.
- **DNS record not created:** it's published ~30s before the dial.
- **ELB timing:** how fast the ELB appeared doesn't separate passing runs from failing ones (median 9s vs 4s,
  heavily overlapping).
- **Squid blocking CONNECT to port 80:** Squid's config allows CONNECT for any authenticated client, and grpc-go
  does send the proxy credentials.

### 6. The July shift lines up with the bastion's OS update

The CI bastion runs whatever Fedora CoreOS **stable** is current when the job runs. The AMI is looked up live
from `builds.coreos.fedoraproject.org/streams/stable.json` in `aws-provision-bastionhost-commands.sh`, and Squid
runs on it in podman `--net host`, resolving via systemd-resolved. Joining each run's `AMI ID:` (from the
`aws-provision-bastionhost` build log) to the FCOS build metadata gives:

| Bastion FCOS stable build | Runs | gRPC failed |
|---|---|---|
| 44.20260510.3.1 | 6 | 1 |
| 44.20260523.3.1 | 18 | 5 |
| 44.20260607.3.1 | 10 | 5 |
| 44.20260621.3.1 | 13 | 4 |
| **44.20260707.3.1** (first used 2026-07-21) | 35 | **31** |
| 44.20260720.3.1 and every later build | 137 | **137** |

This holds in every region (us-east-1, us-east-2, us-west-1, us-west-2) and on both main and release-4.22.
The four passes on 44.20260707.3.1 are the job's last passes (#1829 ×3, #1855).

Package changes from 44.20260621.3.1 to 44.20260707.3.1 that could plausibly matter:

- kernel **7.0.12 → 7.1.3**
- systemd / systemd-resolved 259.6 → 259.7
- podman 5.8.2 → 5.8.4, runc 1.4.2 → 1.5.0, containerd 2.2.3 → 2.3.2
- selinux-policy 44.3 → 44.4, container-selinux 2.249 → 2.250

Nothing relevant turned up in the coreos/fedora-coreos-tracker issues.

Note: the earlier "VPC resolver caches NXDOMAIN for 15 min" idea is probably wrong as stated. Before the shard's
`*.<ns>.apps` record exists, the name should still match the default `*.apps` wildcard and resolve to the
*default* router's ELB, not NXDOMAIN. The mechanism is still open. What the data shows is that the bastion OS
version decides how often the test fails.

## Reproduction on a cluster-bot cluster (2026-10-07)

**Setup:** an AWS IPI cluster (4.22.17, us-west-2, RHCOS 9.8 nodes). A "fake bastion" runs as a host-network pod on a
worker, using CI's exact Squid image (`quay.io/openshifttest/squid-proxy:4.13-fc31`) and squid.conf with proxy
auth. It resolves via the node's VPC resolver (`10.0.0.2`); no systemd-resolved is involved. The real
`openshift-tests run-test "<gRPC test>"` (from the cluster's payload) ran on a laptop with
`HTTP(S)_PROXY` → `oc port-forward` → Squid. A monitor ran `dig @10.0.0.2` and a Squid CONNECT for the test's
hostname every few seconds.

**Result: the hang reproduced.**

| UTC | What happened |
|---|---|
| 14:11:17 | Test namespace created. The hostname resolves via the default `*.apps` wildcard to the **default** router's ELB. The default router has no namespace selector, so it serves the test's routes. |
| 14:11:31 | Ingress-operator publishes the shard's `*.<ns>.apps` CNAME → a brand-new shard ELB. |
| 14:12:05–14:12:20 | 12 of 13 h2c cases pass, still going via the default router (cached A record, TTL 60). |
| 14:12:20 | The cached answer expires and Squid looks the name up again. **The VPC resolver returns NOERROR with no answer**, plus the private zone's SOA (`... 1 7200 900 1209600 86400`, TTL 900). Squid answers every CONNECT with `NONE/503`. The 13th gRPC dial hangs in `grpc.Dial(WithBlock)`. |
| 14:16:48 | A **never-queried** name under the same shard wildcard resolves fine via the same VPC resolver, while the test's hostname still returns the empty answer. That's a cached negative entry for that one name, not a missing record. |
| 14:17:21 | The VPC resolver answers again (~5 min of negative caching). |
| ~14:17:36 | Squid's own negative cache (`negative_dns_ttl`, 1 min default) expires. CONNECTs reach the shard ELB. |
| 14:17:39 | The dial completes. edge, reencrypt and passthrough take ~20s each. **Test passes after a 5m19s stall.** |

**What this shows:**

- **The core mechanism:** a lookup of the test hostname happens while the shard's DNS is switching over. The new
  CNAME points at a just-created ELB whose name most likely doesn't resolve yet. That lookup comes back empty,
  and the empty answer gets cached at the resolvers between Squid and Route53. Squid then refuses every CONNECT,
  and the gRPC dial (no timeout, `WithBlock`) sits in reconnect backoff. This explains why the http2 test was
  fixed by "wait until DNS resolves before the first request", and why normal jobs aren't affected: they resolve
  through the CI cluster's CoreDNS, not the VPC resolver plus a proxy.
- **On this RHCOS "bastion" the stall was ~5 minutes**, so the test survives CI's 15-minute limit. In CI the stall
  is >14.5 minutes. The obvious difference is that the CI bastion is Fedora CoreOS, where Squid's lookups go
  through **systemd-resolved** (127.0.0.53), an extra caching layer that could honor the zone's 900s
  negative TTL. That would also explain the FCOS-version correlation. **Not verified yet.** The systemd
  v259.6 → v259.7 changelog has nothing obviously cache-related.
- In CI the stall hits the **first** dial, about 33s after the shard CNAME is published. Here it hit the 13th, because the
  earlier dials went through the default-router wildcard. Same mechanism, different moment.

### Adding systemd-resolved, as on the CI FCOS bastion

**Setup:** same fake bastion, but Squid's nameserver is `127.0.0.53`, served by systemd-resolved (exact Fedora 44
builds from koji, run in a sidecar) with upstream `DNS=10.0.0.2`. That's how the CI FCOS bastion resolves.

**resolved 259.7-1.fc44** (the version on FCOS builds where every run failed):

| UTC | What happened |
|---|---|
| 14:44:31 | VPC resolver returns the empty answer for the test hostname. |
| 14:44:38 | resolved returns it too. Squid `503`s. The test is stuck dialing. resolved logs `Added NODATA cache entry for grpc-interop-edge.<ns>.apps... IN A 900s`. |
| 14:49:33 | **VPC resolver recovers** (~5 min, same as before). |
| 14:59:41 | **resolved recovers: 15 min**, the full SOA negative TTL. Squid connects at 14:59:55. |

The test started at ~14:43:25. CI's 15-minute per-test limit would have killed it at ~14:58:25, **before recovery**.
That's exactly CI's failure.

**resolved 259.6-1.fc44** (the version on the last FCOS build that was "only" ~30% flaky): the first dial
got stuck right away, like in CI, and resolved logged the same `Added NODATA cache entry ... 900s`. So the
systemd version is **not** what changed in July. Both cache the NODATA for 15 minutes. Something else in the
FCOS 44.20260707 update (kernel 7.0 → 7.1?) changed how often the test lands in the bad window. That part is
still unexplained, but it doesn't matter for the fix.

## Fix: drop the proxy from the recert workflow (openshift/release)

The bastion was added to `openshift-e2e-aws-single-node-recert` in openshift/release#74703 (MGMT-23199) so recert
logs can be fetched over SSH. That PR also added `proxy-config-generate`, but nothing needs an HTTP proxy:

- The cluster is public (`publish` unset → External), so the API and ingress are reachable directly.
- Every step that reads `${SHARED_DIR}/proxy-conf.sh` (install, e2e, gather, deprovision) only sources it if it exists.
- The recert step's SSH goes via the bastion's SSH `ProxyCommand`, not Squid.
- Plain AWS SNO jobs (no proxy) pass the gRPC test ~100%.

Change (branch `recert-workflow-drop-proxy` in `~/repos/release`):

```diff
     - ref: ipi-conf-aws-custom-security-groups
-    - ref: proxy-config-generate
     - chain: aws-provision-iam-user-minimal-permission
```

The bastion stays, so SSH log gathering keeps working. The openshift/release PR's rehearsal of
`e2e-aws-ovn-single-node-recert-parallel` will validate it.

Optional follow-up in the same area: `single-node-recert-commands.sh` has an unexplained `sleep 7200` (added in
the same PR, #74703) that costs 2h per run.

The origin-side hardening (DNS wait + dial timeout in `grpc-interop.go`) is still worth doing, but it's no longer
needed to unblock this job.

## Open questions

1. Is it really a cached "no such name" answer at the VPC resolver, rather than something else on the Squid → ELB path?
   We have no client-side or Squid logs.
2. What changed around July 16–20 that turned "flaky" into "always fails", on both main and release-4.22?
   It's environmental or timing-related, not the PR and not the payload.

## Proposed next steps

1. **Fix in origin** (`test/extended/router/grpc-interop.go`): call `resolveHost(oc, 2*time.Second, 10*time.Minute, host)`
   before dialing, like `http2.go`, and give `grpcinterop.Dial` a deadline (`grpc.DialContext` with
   `context.WithTimeout`) so the retry poll actually retries.
2. **Verify before merging:** run this job against the origin PR from a recert PR via
   `/testwith openshift/origin/main/... openshift/origin#<pr>`. If gRPC goes green, that confirms the explanation.
   Alternatively, rehearse with `GRPC_GO_LOG_SEVERITY_LEVEL=info GRPC_GO_LOG_VERBOSITY_LEVEL=2` to see the dial errors directly.
3. **Backport** the http2 DNS wait (`0c13a1b511`) and the gRPC fix to origin release-4.22.

## Side findings

- `single-node-recert-commands.sh` has an unconditional `sleep 7200` (line 233) before creating the recert
  MachineConfig. That's 2h of every ~7h run.
- Since ~Sept 2025, every merged recert PR that actually ran this job used `/override` to merge. PRs merged
  without one only touched `.konflux/`, `.tekton/` or OWNERS, and the job was skipped for them.

## Data sources

- Prow job history (main: 408 runs since 2026-04-10; 6 passed).
- `test-failures-summary_*.json`, `junit_e2e__*.xml`, and gather-extra ingress-operator / cloud-controller-manager logs.
  These come from `test-platform-results-public` and, through gcsweb with SSO, from `test-platform-results`.
- Sippy `/api/tests/details` for 4.22 and 5.0.
