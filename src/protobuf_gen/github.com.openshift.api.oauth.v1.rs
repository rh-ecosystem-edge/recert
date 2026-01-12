/// ClusterRoleScopeRestriction describes restrictions on cluster role scopes
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClusterRoleScopeRestriction {
    /// RoleNames is the list of cluster roles that can referenced.  * means anything
    #[prost(string, repeated, tag = "1")]
    pub role_names: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Namespaces is the list of namespaces that can be referenced.  * means any of them (including *)
    #[prost(string, repeated, tag = "2")]
    pub namespaces: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// AllowEscalation indicates whether you can request roles and their escalating resources
    #[prost(bool, optional, tag = "3")]
    pub allow_escalation: ::core::option::Option<bool>,
}
/// OAuthAccessToken describes an OAuth access token.
/// The name of a token must be prefixed with a `sha256~` string, must not contain "/" or "%" characters and must be at
/// least 32 characters long.
///
/// The name of the token is constructed from the actual token by sha256-hashing it and using URL-safe unpadded
/// base64-encoding (as described in RFC4648) on the hashed result.
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OAuthAccessToken {
    /// metadata is the standard object's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    >,
    /// ClientName references the client that created this token.
    #[prost(string, optional, tag = "2")]
    pub client_name: ::core::option::Option<::prost::alloc::string::String>,
    /// ExpiresIn is the seconds from CreationTime before this token expires.
    #[prost(int64, optional, tag = "3")]
    pub expires_in: ::core::option::Option<i64>,
    /// Scopes is an array of the requested scopes.
    #[prost(string, repeated, tag = "4")]
    pub scopes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// RedirectURI is the redirection associated with the token.
    #[prost(string, optional, tag = "5")]
    pub redirect_uri: ::core::option::Option<::prost::alloc::string::String>,
    /// UserName is the user name associated with this token
    #[prost(string, optional, tag = "6")]
    pub user_name: ::core::option::Option<::prost::alloc::string::String>,
    /// UserUID is the unique UID associated with this token
    #[prost(string, optional, tag = "7")]
    pub user_uid: ::core::option::Option<::prost::alloc::string::String>,
    /// AuthorizeToken contains the token that authorized this token
    #[prost(string, optional, tag = "8")]
    pub authorize_token: ::core::option::Option<::prost::alloc::string::String>,
    /// RefreshToken is the value by which this token can be renewed. Can be blank.
    #[prost(string, optional, tag = "9")]
    pub refresh_token: ::core::option::Option<::prost::alloc::string::String>,
    /// InactivityTimeoutSeconds is the value in seconds, from the
    /// CreationTimestamp, after which this token can no longer be used.
    /// The value is automatically incremented when the token is used.
    #[prost(int32, optional, tag = "10")]
    pub inactivity_timeout_seconds: ::core::option::Option<i32>,
}
/// OAuthAccessTokenList is a collection of OAuth access tokens
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OAuthAccessTokenList {
    /// metadata is the standard list's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ListMeta,
    >,
    /// Items is the list of OAuth access tokens
    #[prost(message, repeated, tag = "2")]
    pub items: ::prost::alloc::vec::Vec<OAuthAccessToken>,
}
/// OAuthAuthorizeToken describes an OAuth authorization token
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OAuthAuthorizeToken {
    /// metadata is the standard object's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    >,
    /// ClientName references the client that created this token.
    #[prost(string, optional, tag = "2")]
    pub client_name: ::core::option::Option<::prost::alloc::string::String>,
    /// ExpiresIn is the seconds from CreationTime before this token expires.
    #[prost(int64, optional, tag = "3")]
    pub expires_in: ::core::option::Option<i64>,
    /// Scopes is an array of the requested scopes.
    #[prost(string, repeated, tag = "4")]
    pub scopes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// RedirectURI is the redirection associated with the token.
    #[prost(string, optional, tag = "5")]
    pub redirect_uri: ::core::option::Option<::prost::alloc::string::String>,
    /// State data from request
    #[prost(string, optional, tag = "6")]
    pub state: ::core::option::Option<::prost::alloc::string::String>,
    /// UserName is the user name associated with this token
    #[prost(string, optional, tag = "7")]
    pub user_name: ::core::option::Option<::prost::alloc::string::String>,
    /// UserUID is the unique UID associated with this token. UserUID and UserName must both match
    /// for this token to be valid.
    #[prost(string, optional, tag = "8")]
    pub user_uid: ::core::option::Option<::prost::alloc::string::String>,
    /// CodeChallenge is the optional code_challenge associated with this authorization code, as described in rfc7636
    #[prost(string, optional, tag = "9")]
    pub code_challenge: ::core::option::Option<::prost::alloc::string::String>,
    /// CodeChallengeMethod is the optional code_challenge_method associated with this authorization code, as described in rfc7636
    #[prost(string, optional, tag = "10")]
    pub code_challenge_method: ::core::option::Option<::prost::alloc::string::String>,
}
/// OAuthAuthorizeTokenList is a collection of OAuth authorization tokens
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OAuthAuthorizeTokenList {
    /// metadata is the standard list's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ListMeta,
    >,
    /// Items is the list of OAuth authorization tokens
    #[prost(message, repeated, tag = "2")]
    pub items: ::prost::alloc::vec::Vec<OAuthAuthorizeToken>,
}
/// OAuthClient describes an OAuth client
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OAuthClient {
    /// metadata is the standard object's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    >,
    /// Secret is the unique secret associated with a client
    #[prost(string, optional, tag = "2")]
    pub secret: ::core::option::Option<::prost::alloc::string::String>,
    /// AdditionalSecrets holds other secrets that may be used to identify the client.  This is useful for rotation
    /// and for service account token validation
    #[prost(string, repeated, tag = "3")]
    pub additional_secrets: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// RespondWithChallenges indicates whether the client wants authentication needed responses made in the form of challenges instead of redirects
    #[prost(bool, optional, tag = "4")]
    pub respond_with_challenges: ::core::option::Option<bool>,
    /// RedirectURIs is the valid redirection URIs associated with a client
    /// +patchStrategy=merge
    #[prost(string, repeated, tag = "5")]
    pub redirect_ur_is: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// GrantMethod is a required field which determines how to handle grants for this client.
    /// Valid grant handling methods are:
    ///   - auto:   always approves grant requests, useful for trusted clients
    ///   - prompt: prompts the end user for approval of grant requests, useful for third-party clients
    #[prost(string, optional, tag = "6")]
    pub grant_method: ::core::option::Option<::prost::alloc::string::String>,
    /// ScopeRestrictions describes which scopes this client can request.  Each requested scope
    /// is checked against each restriction.  If any restriction matches, then the scope is allowed.
    /// If no restriction matches, then the scope is denied.
    #[prost(message, repeated, tag = "7")]
    pub scope_restrictions: ::prost::alloc::vec::Vec<ScopeRestriction>,
    /// AccessTokenMaxAgeSeconds overrides the default access token max age for tokens granted to this client.
    /// 0 means no expiration.
    #[prost(int32, optional, tag = "8")]
    pub access_token_max_age_seconds: ::core::option::Option<i32>,
    /// AccessTokenInactivityTimeoutSeconds overrides the default token
    /// inactivity timeout for tokens granted to this client.
    /// The value represents the maximum amount of time that can occur between
    /// consecutive uses of the token. Tokens become invalid if they are not
    /// used within this temporal window. The user will need to acquire a new
    /// token to regain access once a token times out.
    /// This value needs to be set only if the default set in configuration is
    /// not appropriate for this client. Valid values are:
    /// - 0: Tokens for this client never time out
    /// - X: Tokens time out if there is no activity for X seconds
    /// The current minimum allowed value for X is 300 (5 minutes)
    ///
    /// WARNING: existing tokens' timeout will not be affected (lowered) by changing this value
    #[prost(int32, optional, tag = "9")]
    pub access_token_inactivity_timeout_seconds: ::core::option::Option<i32>,
}
/// OAuthClientAuthorization describes an authorization created by an OAuth client
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OAuthClientAuthorization {
    /// metadata is the standard object's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    >,
    /// ClientName references the client that created this authorization
    #[prost(string, optional, tag = "2")]
    pub client_name: ::core::option::Option<::prost::alloc::string::String>,
    /// UserName is the user name that authorized this client
    #[prost(string, optional, tag = "3")]
    pub user_name: ::core::option::Option<::prost::alloc::string::String>,
    /// UserUID is the unique UID associated with this authorization. UserUID and UserName
    /// must both match for this authorization to be valid.
    #[prost(string, optional, tag = "4")]
    pub user_uid: ::core::option::Option<::prost::alloc::string::String>,
    /// Scopes is an array of the granted scopes.
    #[prost(string, repeated, tag = "5")]
    pub scopes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// OAuthClientAuthorizationList is a collection of OAuth client authorizations
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OAuthClientAuthorizationList {
    /// metadata is the standard list's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ListMeta,
    >,
    /// Items is the list of OAuth client authorizations
    #[prost(message, repeated, tag = "2")]
    pub items: ::prost::alloc::vec::Vec<OAuthClientAuthorization>,
}
/// OAuthClientList is a collection of OAuth clients
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OAuthClientList {
    /// metadata is the standard list's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ListMeta,
    >,
    /// Items is the list of OAuth clients
    #[prost(message, repeated, tag = "2")]
    pub items: ::prost::alloc::vec::Vec<OAuthClient>,
}
/// OAuthRedirectReference is a reference to an OAuth redirect object.
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OAuthRedirectReference {
    /// metadata is the standard object's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    >,
    /// The reference to an redirect object in the current namespace.
    #[prost(message, optional, tag = "2")]
    pub reference: ::core::option::Option<RedirectReference>,
}
/// RedirectReference specifies the target in the current namespace that resolves into redirect URIs.  Only the 'Route' kind is currently allowed.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RedirectReference {
    /// The group of the target that is being referred to.
    #[prost(string, optional, tag = "1")]
    pub group: ::core::option::Option<::prost::alloc::string::String>,
    /// The kind of the target that is being referred to.  Currently, only 'Route' is allowed.
    #[prost(string, optional, tag = "2")]
    pub kind: ::core::option::Option<::prost::alloc::string::String>,
    /// The name of the target that is being referred to. e.g. name of the Route.
    #[prost(string, optional, tag = "3")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
}
/// ScopeRestriction describe one restriction on scopes.  Exactly one option must be non-nil.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ScopeRestriction {
    /// ExactValues means the scope has to match a particular set of strings exactly
    #[prost(string, repeated, tag = "1")]
    pub literals: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// ClusterRole describes a set of restrictions for cluster role scoping.
    #[prost(message, optional, tag = "2")]
    pub cluster_role: ::core::option::Option<ClusterRoleScopeRestriction>,
}
/// UserOAuthAccessToken is a virtual resource to mirror OAuthAccessTokens to
/// the user the access token was issued for
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserOAuthAccessToken {
    /// metadata is the standard object's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    >,
    /// ClientName references the client that created this token.
    #[prost(string, optional, tag = "2")]
    pub client_name: ::core::option::Option<::prost::alloc::string::String>,
    /// ExpiresIn is the seconds from CreationTime before this token expires.
    #[prost(int64, optional, tag = "3")]
    pub expires_in: ::core::option::Option<i64>,
    /// Scopes is an array of the requested scopes.
    #[prost(string, repeated, tag = "4")]
    pub scopes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// RedirectURI is the redirection associated with the token.
    #[prost(string, optional, tag = "5")]
    pub redirect_uri: ::core::option::Option<::prost::alloc::string::String>,
    /// UserName is the user name associated with this token
    #[prost(string, optional, tag = "6")]
    pub user_name: ::core::option::Option<::prost::alloc::string::String>,
    /// UserUID is the unique UID associated with this token
    #[prost(string, optional, tag = "7")]
    pub user_uid: ::core::option::Option<::prost::alloc::string::String>,
    /// AuthorizeToken contains the token that authorized this token
    #[prost(string, optional, tag = "8")]
    pub authorize_token: ::core::option::Option<::prost::alloc::string::String>,
    /// RefreshToken is the value by which this token can be renewed. Can be blank.
    #[prost(string, optional, tag = "9")]
    pub refresh_token: ::core::option::Option<::prost::alloc::string::String>,
    /// InactivityTimeoutSeconds is the value in seconds, from the
    /// CreationTimestamp, after which this token can no longer be used.
    /// The value is automatically incremented when the token is used.
    #[prost(int32, optional, tag = "10")]
    pub inactivity_timeout_seconds: ::core::option::Option<i32>,
}
/// UserOAuthAccessTokenList is a collection of access tokens issued on behalf of
/// the requesting user
///
/// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
/// +openshift:compatibility-gen:level=1
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserOAuthAccessTokenList {
    /// metadata is the standard list's metadata.
    /// More info: <https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata>
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<
        super::super::super::super::super::super::k8s::io::apimachinery::pkg::apis::meta::v1::ListMeta,
    >,
    #[prost(message, repeated, tag = "2")]
    pub items: ::prost::alloc::vec::Vec<UserOAuthAccessToken>,
}
