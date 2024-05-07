pub mod github {
    pub mod com {
        pub mod openshift {
            pub mod api {
                pub mod oauth {
                    pub mod v1 {
                        include!("github.com.openshift.api.oauth.v1.rs");
                    }
                }
                pub mod route {
                    pub mod v1 {
                        include!("github.com.openshift.api.route.v1.rs");
                    }
                }
            }
        }
    }
}
pub mod k8s {
    pub mod io {
        pub mod api {
            pub mod admissionregistration {
                pub mod v1 {
                    include!("k8s.io.api.admissionregistration.v1.rs");
                }
            }
            pub mod apps {
                pub mod v1 {
                    include!("k8s.io.api.apps.v1.rs");
                }
            }
            pub mod batch {
                pub mod v1 {
                    include!("k8s.io.api.batch.v1.rs");
                }
            }
            pub mod core {
                pub mod v1 {
                    include!("k8s.io.api.core.v1.rs");
                }
            }
        }
        pub mod apimachinery {
            pub mod pkg {
                pub mod api {
                    pub mod resource {
                        include!("k8s.io.apimachinery.pkg.api.resource.rs");
                    }
                }
                pub mod apis {
                    pub mod meta {
                        pub mod v1 {
                            include!("k8s.io.apimachinery.pkg.apis.meta.v1.rs");
                        }
                    }
                }
                pub mod runtime {
                    include!("k8s.io.apimachinery.pkg.runtime.rs");
                }
                pub mod util {
                    pub mod intstr {
                        include!("k8s.io.apimachinery.pkg.util.intstr.rs");
                    }
                }
            }
        }
    }
}
