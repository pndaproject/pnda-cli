Security material put in this directory can be used to configure security on PNDA.
It should include the certificate (chain) needed to validate the security material for securing PNDA services.
So, it should contain:
1. A file with a .crt extension and content in PEM format (Privacy-enhanced Electronic Mail): Base64 encoded DER certificate (chain) enclosed between "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
