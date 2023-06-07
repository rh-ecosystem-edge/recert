use std::collections::HashSet;

use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref IGNORE_LIST_CONFIGMAP: HashSet<String> = vec![
        "verifier-public-key-redhat",
        // "service-account-001.pub",
        // "service-account-002.pub",
        // "ca-bundle.crt"
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    pub(crate) static ref IGNORE_LIST_SECRET: HashSet<String> = vec![
        "prometheus.yaml.gz",
        "alertmanager.yaml.gz",
        "entitlement.pem",
        "entitlement-key.pem",
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    // It's okay for some certs to not have a private key, as it's used to sign a few certs and
    // then dropped by its creator. For us it just means we still have to temporarily recreate them
    // in order to regenerate their signees, we just don't have to record them back to the
    // filesystem or etcd because they were never there in the first place. These are rare so we
    // explicitly record them here and any time we encounter a cert without a matching private key
    // we check if it's in this list and panic if it's not, as it means we might have a bug in our
    // code.
    pub(crate) static ref KNOWN_MISSING_PRIVATE_KEY_CERTS: HashSet<String> = vec![
        // This is a self-signed cert trusted by the kube-apiserver and its private key is used to
        // sign just the admin kubeconfig client cert once and then drops it because there will
        // always ever be only one admin kubeconfig
        "CN=admin-kubeconfig-signer, OU=openshift",
        // TODO: Unknown why it's missing
        "CN=kubelet-bootstrap-kubeconfig-signer, OU=openshift",
        // TODO: Unknown why it's missing
        "CN=root-ca, OU=openshift",
        // As of OCP 4.14 you can see the private key being dropped here:
        // https://github.com/operator-framework/operator-lifecycle-manager/blob/9ced412f3e263b8827680dc0ad3477327cd9a508/pkg/controller/install/certresources.go#L295
        "CN=olm-selfsigned-[0-9a-f]{16}, O=Red Hat, Inc.",
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    // TODO: Find a better way to identify these rather than maintaining this big list
    pub(crate) static ref EXTERNAL_CERTS: HashSet<String> = vec![
        "undecodable", // Some CA use Teletex encoding for their subject and our x509 lib doesn't like dealing with that
        "CN=GlobalSign, OU=GlobalSign ECC Root CA - R5, O=GlobalSign",
        "CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES",
        "CN=Network Solutions Certificate Authority, O=Network Solutions L.L.C., C=US",
        "CN=IdenTrust Commercial Root CA 1, O=IdenTrust, C=US",
        "CN=AC RAIZ FNMT-RCM SERVIDORES SEGUROS, OU=Ceres, O=FNMT-RCM, C=ES",
        "CN=Certum Trusted Network CA 2, OU=Certum Certification Authority, O=Unizeto Technologies S.A., C=PL",
        "CN=Secure Global CA, O=SecureTrust Corporation, C=US",
        "CN=IdenTrust Public Sector Root CA 1, O=IdenTrust, C=US",
        "CN=HARICA TLS RSA Root CA 2021, O=Hellenic Academic and Research Institutions CA, C=GR",
        "CN=COMODO Certification Authority, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB",
        "CN=Certum Trusted Network CA, OU=Certum Certification Authority, O=Unizeto Technologies S.A., C=PL",
        "CN=OISTE WISeKey Global Root GC CA, OU=OISTE Foundation Endorsed, O=WISeKey, C=CH",
        "CN=QuoVadis Root CA 1 G3, O=QuoVadis Limited, C=BM",
        "CN=emSign ECC Root CA - G3, OU=emSign PKI, O=eMudhra Technologies Limited, C=IN",
        "CN=GLOBALTRUST 2020, O=e-commerce monitoring GmbH, C=AT",
        "CN=Buypass Class 3 Root CA, O=Buypass AS-983163327, C=NO",
        "CN=SZAFIR ROOT CA2, O=Krajowa Izba Rozliczeniowa S.A., C=PL",
        "OU=ePKI Root Certification Authority, O=Chunghwa Telecom Co., Ltd., C=TW",
        "CN=HiPKI Root CA - G1, O=Chunghwa Telecom Co., Ltd., C=TW",
        "CN=Certigna, O=Dhimyotis, C=FR",
        "CN=DigiCert Global Root G3, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "CN=Autoridad de Certificacion Firmaprofesional CIF A62634068, C=ES",
        "CN=D-TRUST EV Root CA 1 2020, O=D-Trust GmbH, C=DE",
        "CN=Trustwave Global ECC P256 Certification Authority, O=Trustwave Holdings, Inc., L=Chicago, S=Illinois, C=US",
        "CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "CN=OISTE WISeKey Global Root GB CA, OU=OISTE Foundation Endorsed, O=WISeKey, C=CH",
        "CN=UCA Extended Validation Root, O=UniTrust, C=CN",
        "CN=SwissSign Gold CA - G2, O=SwissSign AG, C=CH",
        "CN=TWCA Root Certification Authority, OU=Root CA, O=TAIWAN-CA, C=TW",
        "CN=ISRG Root X1, O=Internet Security Research Group, C=US",
        "CN=Buypass Class 2 Root CA, O=Buypass AS-983163327, C=NO",
        "CN=DigiCert High Assurance EV Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "CN=D-TRUST BR Root CA 1 2020, O=D-Trust GmbH, C=DE",
        "CN=Microsoft ECC Root Certificate Authority 2017, O=Microsoft Corporation, C=US",
        "CN=QuoVadis Root CA 3 G3, O=QuoVadis Limited, C=BM",
        "CN=TrustCor RootCert CA-1, OU=TrustCor Certificate Authority, O=TrustCor Systems S. de R.L., L=Panama City, S=Panama, C=PA",
        "CN=Starfield Root Certificate Authority - G2, O=Starfield Technologies, Inc., L=Scottsdale, S=Arizona, C=US",
        "CN=Entrust Root Certification Authority, OU=www.entrust.net/CPS is incorporated by reference, OU=(c) 2006 Entrust, Inc., O=Entrust, Inc., C=US",
        "CN=Entrust Root Certification Authority - G2, OU=See www.entrust.net/legal-terms, OU=(c) 2009 Entrust, Inc. - for authorized use only, O=Entrust, Inc., C=US",
        "CN=Actalis Authentication Root CA, O=Actalis S.p.A./03358520967, L=Milan, C=IT",
        "CN=emSign ECC Root CA - C3, OU=emSign PKI, O=eMudhra Inc, C=US",
        "CN=TWCA Global Root CA, OU=Root CA, O=TAIWAN-CA, C=TW",
        "CN=Certigna Root CA, OU=0002 48146308100036, O=Dhimyotis, C=FR",
        "CN=ISRG Root X2, O=Internet Security Research Group, C=US",
        "CN=Staat der Nederlanden EV Root CA, O=Staat der Nederlanden, C=NL",
        "CN=DigiCert Assured ID Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "OU=certSIGN ROOT CA, O=certSIGN, C=RO",
        "CN=XRamp Global Certification Authority, OU=www.xrampsecurity.com, O=XRamp Security Services Inc, C=US",
        "CN=emSign Root CA - C1, OU=emSign PKI, O=eMudhra Inc, C=US",
        "CN=CFCA EV ROOT, O=China Financial Certification Authority, C=CN",
        "CN=Starfield Services Root Certificate Authority - G2, O=Starfield Technologies, Inc., L=Scottsdale, S=Arizona, C=US",
        "CN=QuoVadis Root CA 2, O=QuoVadis Limited, C=BM",
        "CN=GlobalSign Root CA, OU=Root CA, O=GlobalSign nv-sa, C=BE",
        "CN=GlobalSign, OU=GlobalSign Root CA - R3, O=GlobalSign",
        "CN=GlobalSign, OU=GlobalSign Root CA - R6, O=GlobalSign",
        "CN=TeliaSonera Root CA v1, O=TeliaSonera",
        "CN=NetLock Arany (Class Gold) Főtanúsítvány, OU=Tanúsítványkiadók (Certification Services), O=NetLock Kft., L=Budapest, C=HU",
        "CN=D-TRUST Root Class 3 CA 2 EV 2009, O=D-Trust GmbH, C=DE",
        "CN=T-TeleSec GlobalRoot Class 3, OU=T-Systems Trust Center, O=T-Systems Enterprise Services GmbH, C=DE",
        "CN=SecureTrust CA, O=SecureTrust Corporation, C=US",
        "CN=SSL.com EV Root Certification Authority ECC, O=SSL Corporation, L=Houston, S=Texas, C=US",
        "CN=GTS Root R1, O=Google Trust Services LLC, C=US",
        "CN=GTS Root R2, O=Google Trust Services LLC, C=US",
        "CN=DigiCert Assured ID Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "CN=Telia Root CA v2, O=Telia Finland Oyj, C=FI",
        "CN=GDCA TrustAUTH R5 ROOT, O=GUANG DONG CERTIFICATE AUTHORITY CO.,LTD., C=CN",
        "CN=Entrust Root Certification Authority - EC1, OU=See www.entrust.net/legal-terms, OU=(c) 2012 Entrust, Inc. - for authorized use only, O=Entrust, Inc., C=US",
        "CN=AffirmTrust Networking, O=AffirmTrust, C=US",
        "OU=Security Communication RootCA1, O=SECOM Trust.net, C=JP",
        "CN=Izenpe.com, O=IZENPE S.A., C=ES",
        "CN=Hongkong Post Root CA 3, O=Hongkong Post, L=Hong Kong, S=Hong Kong, C=HK",
        "CN=QuoVadis Root CA 2 G3, O=QuoVadis Limited, C=BM",
        "CN=ANF Secure Server Root CA, OU=ANF CA Raiz, O=ANF Autoridad de Certificacion, C=ES",
        "CN=SSL.com EV Root Certification Authority RSA R2, O=SSL Corporation, L=Houston, S=Texas, C=US",
        "CN=vTrus ECC Root CA, O=iTrusChina Co.,Ltd., C=CN",
        "CN=T-TeleSec GlobalRoot Class 2, OU=T-Systems Trust Center, O=T-Systems Enterprise Services GmbH, C=DE",
        "CN=Baltimore CyberTrust Root, OU=CyberTrust, O=Baltimore, C=IE",
        "CN=Trustwave Global ECC P384 Certification Authority, O=Trustwave Holdings, Inc., L=Chicago, S=Illinois, C=US",
        "CN=Entrust Root Certification Authority - G4, OU=See www.entrust.net/legal-terms, OU=(c) 2015 Entrust, Inc. - for authorized use only, O=Entrust, Inc., C=US",
        "CN=SecureSign RootCA11, O=Japan Certification Services, Inc., C=JP",
        "CN=NAVER Global Root Certification Authority, O=NAVER BUSINESS PLATFORM Corp., C=KR",
        "OU=Go Daddy Class 2 Certification Authority, O=The Go Daddy Group, Inc., C=US",
        "CN=EC-ACC, OU=Serveis Publics de Certificacio, OU=Vegeu https://www.catcert.net/verarrel (c)03, OU=Jerarquia Entitats de Certificacio Catalanes, O=Agencia Catalana de Certificacio (NIF Q-0801176-I), C=ES",
        "CN=Go Daddy Root Certificate Authority - G2, O=GoDaddy.com, Inc., L=Scottsdale, S=Arizona, C=US",
        "OU=AC RAIZ FNMT-RCM, O=FNMT-RCM, C=ES",
        "CN=DigiCert Assured ID Root G3, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "CN=GlobalSign Root R46, O=GlobalSign nv-sa, C=BE",
        "CN=TrustCor ECA-1, OU=TrustCor Certificate Authority, O=TrustCor Systems S. de R.L., L=Panama City, S=Panama, C=PA",
        "OU=Starfield Class 2 Certification Authority, O=Starfield Technologies, Inc., C=US",
        "CN=COMODO RSA Certification Authority, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB",
        "CN=Hellenic Academic and Research Institutions RootCA 2011, O=Hellenic Academic and Research Institutions Cert. Authority, C=GR",
        "CN=AffirmTrust Premium ECC, O=AffirmTrust, C=US",
        "CN=AffirmTrust Commercial, O=AffirmTrust, C=US",
        "CN=HARICA TLS ECC Root CA 2021, O=Hellenic Academic and Research Institutions CA, C=GR",
        "CN=Amazon Root CA 2, O=Amazon, C=US",
        "CN=E-Tugra Certification Authority, OU=E-Tugra Sertifikasyon Merkezi, O=E-Tuğra EBG Bilişim Teknolojileri ve Hizmetleri A.Ş., L=Ankara, C=TR",
        "CN=Hongkong Post Root CA 1, O=Hongkong Post, C=HK",
        "CN=TrustCor RootCert CA-2, OU=TrustCor Certificate Authority, O=TrustCor Systems S. de R.L., L=Panama City, S=Panama, C=PA",
        "CN=AAA Certificate Services, O=Comodo CA Limited, L=Salford, S=Greater Manchester, C=GB",
        "CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "CN=USERTrust RSA Certification Authority, O=The USERTRUST Network, L=Jersey City, S=New Jersey, C=US",
        "CN=GlobalSign Root E46, O=GlobalSign nv-sa, C=BE",
        "CN=QuoVadis Root CA 3, O=QuoVadis Limited, C=BM",
        "CN=GTS Root R4, O=Google Trust Services LLC, C=US",
        "CN=TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1, OU=Kamu Sertifikasyon Merkezi - Kamu SM, O=Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK, L=Gebze - Kocaeli, C=TR",
        "CN=USERTrust ECC Certification Authority, O=The USERTRUST Network, L=Jersey City, S=New Jersey, C=US",
        "CN=Microsoft RSA Root Certificate Authority 2017, O=Microsoft Corporation, C=US",
        "CN=Certum Trusted Root CA, OU=Certum Certification Authority, O=Asseco Data Systems S.A., C=PL",
        "CN=CA Disig Root R2, O=Disig a.s., L=Bratislava, C=SK",
        "CN=emSign Root CA - G1, OU=emSign PKI, O=eMudhra Technologies Limited, C=IN",
        "CN=Hellenic Academic and Research Institutions RootCA 2015, O=Hellenic Academic and Research Institutions Cert. Authority, L=Athens, C=GR",
        "CN=GTS Root R3, O=Google Trust Services LLC, C=US",
        "CN=UCA Global G2 Root, O=UniTrust, C=CN",
        "CN=Trustwave Global Certification Authority, O=Trustwave Holdings, Inc., L=Chicago, S=Illinois, C=US",
        "CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "CN=Certum EC-384 CA, OU=Certum Certification Authority, O=Asseco Data Systems S.A., C=PL",
        "CN=Hellenic Academic and Research Institutions ECC RootCA 2015, O=Hellenic Academic and Research Institutions Cert. Authority, L=Athens, C=GR",
        "CN=Microsec e-Szigno Root CA 2009, O=Microsec Ltd., L=Budapest, C=HU",
        "CN=e-Szigno Root CA 2017, O=Microsec Ltd., L=Budapest, C=HU",
        "CN=SSL.com Root Certification Authority RSA, O=SSL Corporation, L=Houston, S=Texas, C=US",
        "CN=Amazon Root CA 1, O=Amazon, C=US",
        "CN=COMODO ECC Certification Authority, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB",
        "CN=vTrus Root CA, O=iTrusChina Co.,Ltd., C=CN",
        "CN=SSL.com Root Certification Authority ECC, O=SSL Corporation, L=Houston, S=Texas, C=US",
        "OU=certSIGN ROOT CA G2, O=CERTSIGN SA, C=RO",
        "CN=D-TRUST Root Class 3 CA 2 2009, O=D-Trust GmbH, C=DE",
        "OU=Security Communication RootCA2, O=SECOM Trust Systems CO.,LTD., C=JP",
        "CN=AffirmTrust Premium, O=AffirmTrust, C=US",
        "CN=Amazon Root CA 3, O=Amazon, C=US",
        "CN=SwissSign Silver CA - G2, O=SwissSign AG, C=CH",
        "CN=Amazon Root CA 4, O=Amazon, C=US",
        "CN=TunTrust Root CA, O=Agence Nationale de Certification Electronique, C=TN",
        "CN=Atos TrustedRoot 2011, O=Atos, C=DE",
    ]
        .into_iter()
        .map(str::to_string)
        .collect();
}
