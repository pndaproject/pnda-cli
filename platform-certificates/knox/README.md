Security material put in this directory can be used to configure knox.
It should either be left empty to have knox accessible through http.
Or it should include the private key, the associated certificate and fqdn needed to configure knox for SSL (https).
In the later case, it should contain:
1. A file with a .crt extension and content in PEM format (Privacy-enhanced Electronic Mail): Base64 encoded DER certificate enclosed between "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
2. A file with a .key extension and content in PEM format (Privacy-enhanced Electronic Mail): Base64 encoded DER key enclosed between "-----BEGIN ENCRYPTED PRIVATE KEY-----" and "-----END ENCRYPTED PRIVATE KEY-----"
3. A file with a .yaml extension and content in YAML format. The file should only contain one key and associated value. The key must be 'fqdn' and it's value should be a valid FQDN for the associated certificate. For example:
   ```
   fqdn: knox.service.dc1.pnda.local
   ```
