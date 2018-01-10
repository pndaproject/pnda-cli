Security material put in this directory can be used to configure jupyter.
It should either be left empty to have jupyterhub accessible through http.
Or it should include the private key and associated certificate chain needed to configure jupyterhub for SSL (https).
In the later case, it should contain:
1. A file with a .pem extension and content in PEM format (Privacy-enhanced Electronic Mail): Base64 encoded DER certificate chain (concatenation) with each certificate enclosed between "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
2. A file with a .key extension and content in PEM format (Privacy-enhanced Electronic Mail): Base64 encoded DER key enclosed between "-----BEGIN ENCRYPTED PRIVATE KEY-----" and "-----END ENCRYPTED PRIVATE KEY-----"
