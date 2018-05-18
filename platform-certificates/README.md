Security material put in this directory can be used to configure security on PNDA.
It should either be left empty.
Or it should include the private key and associated certificate (chain) needed to generate the security material for securing PNDA services.
In the later case, it should contain:
1. A file with a .crt extension and content in PEM format (Privacy-enhanced Electronic Mail): Base64 encoded DER certificate (chain) enclosed between "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
2. A file with a .key extension and content in PEM format (Privacy-enhanced Electronic Mail): Base64 encoded DER key enclosed between "-----BEGIN ENCRYPTED PRIVATE KEY-----" and "-----END ENCRYPTED PRIVATE KEY-----"
