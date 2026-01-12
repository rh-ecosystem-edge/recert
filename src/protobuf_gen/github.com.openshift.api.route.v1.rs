/// LocalObjectReference contains enough information to let you locate the
/// referenced object inside the same namespace.
/// +structType=atomic
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LocalObjectReference {
    /// name of the referent.
    /// More info: <https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names>
    /// +optional
    #[prost(string, optional, tag = "1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
}
/// A route allows developers to expose services through an HTTP(S) aware load balancing and proxy
/// layer via a public DNS entry. The route may further specify TLS options and a certificate, or
/// specify a public CNAME that the router should also accept for HTTP and HTTPS traffic. An
/// administrator typically configures their router to be visible outside the cluster firewall, and
/// may also add additional security, caching, or traffic controls on the service content. Routers
/// usually talk directly to the service endpoints.
///
/// Once a route is created, the `host` field may not be changed. Generally, routers use the oldest
/// route with a given host when resolving conflicts.
///
/// Routers are subject to additional customization and may support additional controls via the
/// annotations field.
///
/// Because administrators may configure multiple routers, the route status field is used to
/// return information to clients about the names and states of the route under each router.
/// If a client chooses a duplicate name, for instance, the route status conditions are used
/// to indicate the route cannot be chosen.
///
/// To enable HTTP/2 ALPN on a route it requires a custom
/// (non-wildcard) certificate. This prevents connection coalescing by
/// clients, notably web browsers. We do not support HTTP/2 ALPN on
/// routes that use the default certificate because of the risk of
/// connection re-use/coalescing. Routes that do not have their own
/// custom certificate will not be HTTP/2 ALPN-enabled on either the
/// frontend or the backend.
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Route {
    /// metadata is the standard object's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    >,
    /// spec is the desired state of the route
    /// +kubebuilder:validation:XValidation:rule="!has(self.tls) || self.tls.termination != 'passthrough' || !has(self.httpHeaders)",message="header actions are not permitted when tls termination is passthrough."
    #[prost(message, optional, tag = "2")]
    pub spec: ::core::option::Option<RouteSpec>,
    /// status is the current state of the route
    /// +optional
    #[prost(message, optional, tag = "3")]
    pub status: ::core::option::Option<RouteStatus>,
}
/// RouteHTTPHeader specifies configuration for setting or deleting an HTTP header.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteHttpHeader {
    /// name specifies the name of a header on which to perform an action. Its value must be a valid HTTP header
    /// name as defined in RFC 2616 section 4.2.
    /// The name must consist only of alphanumeric and the following special characters, "-!#$%&'*+.^_`".
    /// The following header names are reserved and may not be modified via this API:
    /// Strict-Transport-Security, Proxy, Cookie, Set-Cookie.
    /// It must be no more than 255 characters in length.
    /// Header name must be unique.
    /// +kubebuilder:validation:Required
    /// +kubebuilder:validation:MinLength=1
    /// +kubebuilder:validation:MaxLength=255
    /// +kubebuilder:validation:Pattern="^\[-!#$%&'*+.0-9A-Z^_`a-z|~\]+$"
    /// +kubebuilder:validation:XValidation:rule="self.lowerAscii() != 'strict-transport-security'",message="strict-transport-security header may not be modified via header actions"
    /// +kubebuilder:validation:XValidation:rule="self.lowerAscii() != 'proxy'",message="proxy header may not be modified via header actions"
    /// +kubebuilder:validation:XValidation:rule="self.lowerAscii() != 'cookie'",message="cookie header may not be modified via header actions"
    /// +kubebuilder:validation:XValidation:rule="self.lowerAscii() != 'set-cookie'",message="set-cookie header may not be modified via header actions"
    #[prost(string, optional, tag = "1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    /// action specifies actions to perform on headers, such as setting or deleting headers.
    /// +kubebuilder:validation:Required
    #[prost(message, optional, tag = "2")]
    pub action: ::core::option::Option<RouteHttpHeaderActionUnion>,
}
/// RouteHTTPHeaderActionUnion specifies an action to take on an HTTP header.
/// +kubebuilder:validation:XValidation:rule="has(self.type) && self.type == 'Set' ?  has(self.set) : !has(self.set)",message="set is required when type is Set, and forbidden otherwise"
/// +union
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteHttpHeaderActionUnion {
    /// type defines the type of the action to be applied on the header.
    /// Possible values are Set or Delete.
    /// Set allows you to set HTTP request and response headers.
    /// Delete allows you to delete HTTP request and response headers.
    /// +unionDiscriminator
    /// +kubebuilder:validation:Enum:=Set;Delete
    /// +kubebuilder:validation:Required
    #[prost(string, optional, tag = "1")]
    pub r#type: ::core::option::Option<::prost::alloc::string::String>,
    /// set defines the HTTP header that should be set: added if it doesn't exist or replaced if it does.
    /// This field is required when type is Set and forbidden otherwise.
    /// +optional
    /// +unionMember
    #[prost(message, optional, tag = "2")]
    pub set: ::core::option::Option<RouteSetHttpHeader>,
}
/// RouteHTTPHeaderActions defines configuration for actions on HTTP request and response headers.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteHttpHeaderActions {
    /// response is a list of HTTP response headers to modify.
    /// Currently, actions may define to either `Set` or `Delete` headers values.
    /// Actions defined here will modify the response headers of all requests made through a route.
    /// These actions are applied to a specific Route defined within a cluster i.e. connections made through a route.
    /// Route actions will be executed before IngressController actions for response headers.
    /// Actions are applied in sequence as defined in this list.
    /// A maximum of 20 response header actions may be configured.
    /// You can use this field to specify HTTP response headers that should be set or deleted
    /// when forwarding responses from your application to the client.
    /// Sample fetchers allowed are "res.hdr" and "ssl_c_der".
    /// Converters allowed are "lower" and "base64".
    /// Example header values: "%\[res.hdr(X-target),lower\]", "%{+Q}\[ssl_c_der,base64\]".
    /// Note: This field cannot be used if your route uses TLS passthrough.
    /// + ---
    /// + Note: Any change to regex mentioned below must be reflected in the CRD validation of route in <https://github.com/openshift/library-go/blob/master/pkg/route/validation/validation.go> and vice-versa.
    /// +listType=map
    /// +listMapKey=name
    /// +optional
    /// +kubebuilder:validation:MaxItems=20
    /// +kubebuilder:validation:XValidation:rule=`self.all(key, key.action.type == "Delete" || (has(key.action.set) && key.action.set.value.matches('^(?:%(?:%|(?:\\{\[-+\]?[QXE](?:,\[-+\]?[QXE])*\\})?\\[(?:res\\.hdr\\(\[0-9A-Za-z-\]+\\)|ssl_c_der)(?:,(?:lower|base64))*\\])|\[^%[:cntrl:]\])+$')))`,message="Either the header value provided is not in correct format or the sample fetcher/converter specified is not allowed. The dynamic header value will be interpreted as an HAProxy format string as defined in <http://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.6> and may use HAProxy's %\[\] syntax and otherwise must be a valid HTTP header value as defined in <https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.> Sample fetchers allowed are res.hdr, ssl_c_der. Converters allowed are lower, base64."
    #[prost(message, repeated, tag = "1")]
    pub response: ::prost::alloc::vec::Vec<RouteHttpHeader>,
    /// request is a list of HTTP request headers to modify.
    /// Currently, actions may define to either `Set` or `Delete` headers values.
    /// Actions defined here will modify the request headers of all requests made through a route.
    /// These actions are applied to a specific Route defined within a cluster i.e. connections made through a route.
    /// Currently, actions may define to either `Set` or `Delete` headers values.
    /// Route actions will be executed after IngressController actions for request headers.
    /// Actions are applied in sequence as defined in this list.
    /// A maximum of 20 request header actions may be configured.
    /// You can use this field to specify HTTP request headers that should be set or deleted
    /// when forwarding connections from the client to your application.
    /// Sample fetchers allowed are "req.hdr" and "ssl_c_der".
    /// Converters allowed are "lower" and "base64".
    /// Example header values: "%\[req.hdr(X-target),lower\]", "%{+Q}\[ssl_c_der,base64\]".
    /// Any request header configuration applied directly via a Route resource using this API
    /// will override header configuration for a header of the same name applied via
    /// spec.httpHeaders.actions on the IngressController or route annotation.
    /// Note: This field cannot be used if your route uses TLS passthrough.
    /// + ---
    /// + Note: Any change to regex mentioned below must be reflected in the CRD validation of route in <https://github.com/openshift/library-go/blob/master/pkg/route/validation/validation.go> and vice-versa.
    /// +listType=map
    /// +listMapKey=name
    /// +optional
    /// +kubebuilder:validation:MaxItems=20
    /// +kubebuilder:validation:XValidation:rule=`self.all(key, key.action.type == "Delete" || (has(key.action.set) && key.action.set.value.matches('^(?:%(?:%|(?:\\{\[-+\]?[QXE](?:,\[-+\]?[QXE])*\\})?\\[(?:req\\.hdr\\(\[0-9A-Za-z-\]+\\)|ssl_c_der)(?:,(?:lower|base64))*\\])|\[^%[:cntrl:]\])+$')))`,message="Either the header value provided is not in correct format or the sample fetcher/converter specified is not allowed. The dynamic header value will be interpreted as an HAProxy format string as defined in <http://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.6> and may use HAProxy's %\[\] syntax and otherwise must be a valid HTTP header value as defined in <https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.> Sample fetchers allowed are req.hdr, ssl_c_der. Converters allowed are lower, base64."
    #[prost(message, repeated, tag = "2")]
    pub request: ::prost::alloc::vec::Vec<RouteHttpHeader>,
}
/// RouteHTTPHeaders defines policy for HTTP headers.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteHttpHeaders {
    /// actions specifies options for modifying headers and their values.
    /// Note that this option only applies to cleartext HTTP connections
    /// and to secure HTTP connections for which the ingress controller
    /// terminates encryption (that is, edge-terminated or reencrypt
    /// connections).  Headers cannot be modified for TLS passthrough
    /// connections.
    /// Setting the HSTS (`Strict-Transport-Security`) header is not supported via actions.
    /// `Strict-Transport-Security` may only be configured using the "haproxy.router.openshift.io/hsts_header"
    /// route annotation, and only in accordance with the policy specified in Ingress.Spec.RequiredHSTSPolicies.
    /// In case of HTTP request headers, the actions specified in spec.httpHeaders.actions on the Route will be executed after
    /// the actions specified in the IngressController's spec.httpHeaders.actions field.
    /// In case of HTTP response headers, the actions specified in spec.httpHeaders.actions on the IngressController will be
    /// executed after the actions specified in the Route's spec.httpHeaders.actions field.
    /// The headers set via this API will not appear in access logs.
    /// Any actions defined here are applied after any actions related to the following other fields:
    /// cache-control, spec.clientTLS,
    /// spec.httpHeaders.forwardedHeaderPolicy, spec.httpHeaders.uniqueId,
    /// and spec.httpHeaders.headerNameCaseAdjustments.
    /// The following header names are reserved and may not be modified via this API:
    /// Strict-Transport-Security, Proxy, Cookie, Set-Cookie.
    /// Note that the total size of all net added headers *after* interpolating dynamic values
    /// must not exceed the value of spec.tuningOptions.headerBufferMaxRewriteBytes on the
    /// IngressController. Please refer to the documentation
    /// for that API field for more details.
    /// +optional
    #[prost(message, optional, tag = "1")]
    pub actions: ::core::option::Option<RouteHttpHeaderActions>,
}
/// RouteIngress holds information about the places where a route is exposed.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteIngress {
    /// Host is the host string under which the route is exposed; this value is required
    #[prost(string, optional, tag = "1")]
    pub host: ::core::option::Option<::prost::alloc::string::String>,
    /// Name is a name chosen by the router to identify itself; this value is required
    #[prost(string, optional, tag = "2")]
    pub router_name: ::core::option::Option<::prost::alloc::string::String>,
    /// Conditions is the state of the route, may be empty.
    #[prost(message, repeated, tag = "3")]
    pub conditions: ::prost::alloc::vec::Vec<RouteIngressCondition>,
    /// Wildcard policy is the wildcard policy that was allowed where this route is exposed.
    #[prost(string, optional, tag = "4")]
    pub wildcard_policy: ::core::option::Option<::prost::alloc::string::String>,
    /// CanonicalHostname is the external host name for the router that can be used as a CNAME
    /// for the host requested for this route. This value is optional and may not be set in all cases.
    #[prost(string, optional, tag = "5")]
    pub router_canonical_hostname: ::core::option::Option<
        ::prost::alloc::string::String,
    >,
}
/// RouteIngressCondition contains details for the current condition of this route on a particular
/// router.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteIngressCondition {
    /// Type is the type of the condition.
    /// Currently only Admitted.
    #[prost(string, optional, tag = "1")]
    pub r#type: ::core::option::Option<::prost::alloc::string::String>,
    /// Status is the status of the condition.
    /// Can be True, False, Unknown.
    #[prost(string, optional, tag = "2")]
    pub status: ::core::option::Option<::prost::alloc::string::String>,
    /// (brief) reason for the condition's last transition, and is usually a machine and human
    /// readable constant
    #[prost(string, optional, tag = "3")]
    pub reason: ::core::option::Option<::prost::alloc::string::String>,
    /// Human readable message indicating details about last transition.
    #[prost(string, optional, tag = "4")]
    pub message: ::core::option::Option<::prost::alloc::string::String>,
    /// RFC 3339 date and time when this condition last transitioned
    #[prost(message, optional, tag = "5")]
    pub last_transition_time: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::Time,
    >,
}
/// RouteList is a collection of Routes.
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteList {
    /// metadata is the standard list's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ListMeta,
    >,
    /// items is a list of routes
    #[prost(message, repeated, tag = "2")]
    pub items: ::prost::alloc::vec::Vec<Route>,
}
/// RoutePort defines a port mapping from a router to an endpoint in the service endpoints.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RoutePort {
    /// The target port on pods selected by the service this route points to.
    /// If this is a string, it will be looked up as a named port in the target
    /// endpoints port list. Required
    #[prost(message, optional, tag = "1")]
    pub target_port: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::util::intstr::IntOrString,
    >,
}
/// RouteSetHTTPHeader specifies what value needs to be set on an HTTP header.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteSetHttpHeader {
    /// value specifies a header value.
    /// Dynamic values can be added. The value will be interpreted as an HAProxy format string as defined in
    /// <http://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.6> and may use HAProxy's %\[\] syntax and
    /// otherwise must be a valid HTTP header value as defined in <https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.>
    /// The value of this field must be no more than 16384 characters in length.
    /// Note that the total size of all net added headers *after* interpolating dynamic values
    /// must not exceed the value of spec.tuningOptions.headerBufferMaxRewriteBytes on the
    /// IngressController.
    /// + ---
    /// + Note: This limit was selected as most common web servers have a limit of 16384 characters or some lower limit.
    /// + See <<https://www.geekersdigest.com/max-http-request-header-size-server-comparison/>.>
    /// +kubebuilder:validation:Required
    /// +kubebuilder:validation:MinLength=1
    /// +kubebuilder:validation:MaxLength=16384
    #[prost(string, optional, tag = "1")]
    pub value: ::core::option::Option<::prost::alloc::string::String>,
}
/// RouteSpec describes the hostname or path the route exposes, any security information,
/// and one to four backends (services) the route points to. Requests are distributed
/// among the backends depending on the weights assigned to each backend. When using
/// roundrobin scheduling the portion of requests that go to each backend is the backend
/// weight divided by the sum of all of the backend weights. When the backend has more than
/// one endpoint the requests that end up on the backend are roundrobin distributed among
/// the endpoints. Weights are between 0 and 256 with default 100. Weight 0 causes no requests
/// to the backend. If all weights are zero the route will be considered to have no backends
/// and return a standard 503 response.
///
/// The `tls` field is optional and allows specific certificates or behavior for the
/// route. Routers typically configure a default certificate on a wildcard domain to
/// terminate routes without explicit certificates, but custom hostnames usually must
/// choose passthrough (send traffic directly to the backend via the TLS Server-Name-
/// Indication field) or provide a certificate.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteSpec {
    /// host is an alias/DNS that points to the service. Optional.
    /// If not specified a route name will typically be automatically
    /// chosen.
    /// Must follow DNS952 subdomain conventions.
    ///
    /// +optional
    /// +kubebuilder:validation:MaxLength=253
    /// +kubebuilder:validation:Pattern=`^(\[a-zA-Z0-9\]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}\[a-zA-Z0-9\])(\.(\[a-zA-Z0-9\]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}\[a-zA-Z0-9\]))*$`
    #[prost(string, optional, tag = "1")]
    pub host: ::core::option::Option<::prost::alloc::string::String>,
    /// subdomain is a DNS subdomain that is requested within the ingress controller's
    /// domain (as a subdomain). If host is set this field is ignored. An ingress
    /// controller may choose to ignore this suggested name, in which case the controller
    /// will report the assigned name in the status.ingress array or refuse to admit the
    /// route. If this value is set and the server does not support this field host will
    /// be populated automatically. Otherwise host is left empty. The field may have
    /// multiple parts separated by a dot, but not all ingress controllers may honor
    /// the request. This field may not be changed after creation except by a user with
    /// the update routes/custom-host permission.
    ///
    /// Example: subdomain `frontend` automatically receives the router subdomain
    /// `apps.mycluster.com` to have a full hostname `frontend.apps.mycluster.com`.
    ///
    /// +optional
    /// +kubebuilder:validation:MaxLength=253
    /// +kubebuilder:validation:Pattern=`^(\[a-zA-Z0-9\]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}\[a-zA-Z0-9\])(\.(\[a-zA-Z0-9\]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}\[a-zA-Z0-9\]))*$`
    #[prost(string, optional, tag = "8")]
    pub subdomain: ::core::option::Option<::prost::alloc::string::String>,
    /// path that the router watches for, to route traffic for to the service. Optional
    ///
    /// +optional
    /// +kubebuilder:validation:Pattern=`^/`
    #[prost(string, optional, tag = "2")]
    pub path: ::core::option::Option<::prost::alloc::string::String>,
    /// to is an object the route should use as the primary backend. Only the Service kind
    /// is allowed, and it will be defaulted to Service. If the weight field (0-256 default 100)
    /// is set to zero, no traffic will be sent to this backend.
    #[prost(message, optional, tag = "3")]
    pub to: ::core::option::Option<RouteTargetReference>,
    /// alternateBackends allows up to 3 additional backends to be assigned to the route.
    /// Only the Service kind is allowed, and it will be defaulted to Service.
    /// Use the weight field in RouteTargetReference object to specify relative preference.
    ///
    /// +kubebuilder:validation:MaxItems=3
    #[prost(message, repeated, tag = "4")]
    pub alternate_backends: ::prost::alloc::vec::Vec<RouteTargetReference>,
    /// If specified, the port to be used by the router. Most routers will use all
    /// endpoints exposed by the service by default - set this value to instruct routers
    /// which port to use.
    #[prost(message, optional, tag = "5")]
    pub port: ::core::option::Option<RoutePort>,
    /// The tls field provides the ability to configure certificates and termination for the route.
    #[prost(message, optional, tag = "6")]
    pub tls: ::core::option::Option<TlsConfig>,
    /// Wildcard policy if any for the route.
    /// Currently only 'Subdomain' or 'None' is allowed.
    ///
    /// +kubebuilder:validation:Enum=None;Subdomain;""
    /// +kubebuilder:default=None
    #[prost(string, optional, tag = "7")]
    pub wildcard_policy: ::core::option::Option<::prost::alloc::string::String>,
    /// httpHeaders defines policy for HTTP headers.
    ///
    /// +optional
    #[prost(message, optional, tag = "9")]
    pub http_headers: ::core::option::Option<RouteHttpHeaders>,
}
/// RouteStatus provides relevant info about the status of a route, including which routers
/// acknowledge it.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteStatus {
    /// ingress describes the places where the route may be exposed. The list of
    /// ingress points may contain duplicate Host or RouterName values. Routes
    /// are considered live once they are `Ready`
    #[prost(message, repeated, tag = "1")]
    pub ingress: ::prost::alloc::vec::Vec<RouteIngress>,
}
/// RouteTargetReference specifies the target that resolve into endpoints. Only the 'Service'
/// kind is allowed. Use 'weight' field to emphasize one over others.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteTargetReference {
    /// The kind of target that the route is referring to. Currently, only 'Service' is allowed
    ///
    /// +kubebuilder:validation:Enum=Service;""
    /// +kubebuilder:default=Service
    #[prost(string, optional, tag = "1")]
    pub kind: ::core::option::Option<::prost::alloc::string::String>,
    /// name of the service/target that is being referred to. e.g. name of the service
    ///
    /// +kubebuilder:validation:MinLength=1
    #[prost(string, optional, tag = "2")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    /// weight as an integer between 0 and 256, default 100, that specifies the target's relative weight
    /// against other target reference objects. 0 suppresses requests to this backend.
    ///
    /// +optional
    /// +kubebuilder:validation:Minimum=0
    /// +kubebuilder:validation:Maximum=256
    /// +kubebuilder:default=100
    #[prost(int32, optional, tag = "3")]
    pub weight: ::core::option::Option<i32>,
}
/// RouterShard has information of a routing shard and is used to
/// generate host names and routing table entries when a routing shard is
/// allocated for a specific route.
/// Caveat: This is WIP and will likely undergo modifications when sharding
/// support is added.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouterShard {
    /// shardName uniquely identifies a router shard in the "set" of
    /// routers used for routing traffic to the services.
    #[prost(string, optional, tag = "1")]
    pub shard_name: ::core::option::Option<::prost::alloc::string::String>,
    /// dnsSuffix for the shard ala: shard-1.v3.openshift.com
    #[prost(string, optional, tag = "2")]
    pub dns_suffix: ::core::option::Option<::prost::alloc::string::String>,
}
/// TLSConfig defines config used to secure a route and provide termination
///
/// +kubebuilder:validation:XValidation:rule="has(self.termination) && has(self.insecureEdgeTerminationPolicy) ? !((self.termination=='passthrough') && (self.insecureEdgeTerminationPolicy=='Allow')) : true", message="cannot have both spec.tls.termination: passthrough and spec.tls.insecureEdgeTerminationPolicy: Allow"
/// +openshift:validation:FeatureSetAwareXValidation:featureSet=TechPreviewNoUpgrade;CustomNoUpgrade,rule="!(has(self.certificate) && has(self.externalCertificate))", message="cannot have both spec.tls.certificate and spec.tls.externalCertificate"
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TlsConfig {
    /// termination indicates termination type.
    ///
    /// * edge - TLS termination is done by the router and http is used to communicate with the backend (default)
    /// * passthrough - Traffic is sent straight to the destination without the router providing TLS termination
    /// * reencrypt - TLS termination is done by the router and https is used to communicate with the backend
    ///
    /// Note: passthrough termination is incompatible with httpHeader actions
    /// +kubebuilder:validation:Enum=edge;reencrypt;passthrough
    #[prost(string, optional, tag = "1")]
    pub termination: ::core::option::Option<::prost::alloc::string::String>,
    /// certificate provides certificate contents. This should be a single serving certificate, not a certificate
    /// chain. Do not include a CA certificate.
    #[prost(string, optional, tag = "2")]
    pub certificate: ::core::option::Option<::prost::alloc::string::String>,
    /// key provides key file contents
    #[prost(string, optional, tag = "3")]
    pub key: ::core::option::Option<::prost::alloc::string::String>,
    /// caCertificate provides the cert authority certificate contents
    #[prost(string, optional, tag = "4")]
    pub ca_certificate: ::core::option::Option<::prost::alloc::string::String>,
    /// destinationCACertificate provides the contents of the ca certificate of the final destination.  When using reencrypt
    /// termination this file should be provided in order to have routers use it for health checks on the secure connection.
    /// If this field is not specified, the router may provide its own destination CA and perform hostname validation using
    /// the short service name (service.namespace.svc), which allows infrastructure generated certificates to automatically
    /// verify.
    #[prost(string, optional, tag = "5")]
    pub destination_ca_certificate: ::core::option::Option<
        ::prost::alloc::string::String,
    >,
    /// insecureEdgeTerminationPolicy indicates the desired behavior for insecure connections to a route. While
    /// each router may make its own decisions on which ports to expose, this is normally port 80.
    ///
    /// * Allow - traffic is sent to the server on the insecure port (edge/reencrypt terminations only) (default).
    /// * None - no traffic is allowed on the insecure port.
    /// * Redirect - clients are redirected to the secure port.
    ///
    /// +kubebuilder:validation:Enum=Allow;None;Redirect;""
    #[prost(string, optional, tag = "6")]
    pub insecure_edge_termination_policy: ::core::option::Option<
        ::prost::alloc::string::String,
    >,
    /// externalCertificate provides certificate contents as a secret reference.
    /// This should be a single serving certificate, not a certificate
    /// chain. Do not include a CA certificate. The secret referenced should
    /// be present in the same namespace as that of the Route.
    /// Forbidden when `certificate` is set.
    ///
    /// +openshift:enable:FeatureSets=CustomNoUpgrade;TechPreviewNoUpgrade
    /// +optional
    #[prost(message, optional, tag = "7")]
    pub external_certificate: ::core::option::Option<LocalObjectReference>,
}
