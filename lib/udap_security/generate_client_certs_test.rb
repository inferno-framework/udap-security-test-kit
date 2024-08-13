require_relative 'udap_x509_certificate'
require_relative 'default_cert_file_loader'

module UDAPSecurityTestKit
  class GenerateClientCertsTest < Inferno::Test
    title 'Generate Client Certificates'
    id :udap_generate_client_certs
    description %(
      This test may be included in test groups to generate and output a new client certificate for use in UDAP dynamic
      client registration or authentication/authorization tests.
    )

    input :udap_client_cert_pem,
          title: 'X.509 Client Certificate(s) (PEM Format)',
          description: %(
            A list of one or more X.509 certificates in PEM format separated by a newline. The first (leaf) certificate
            MUST represent the client entity and the certificate chain must resolve to a CA trusted by the authorization
            server under test.
            Will be auto-generated if left blank.
          ),
          type: 'textarea',
          optional: true

    input :udap_client_private_key_pem,
          title: 'Client Private Key (PEM Format)',
          description: %(
          The private key corresponding to the client certificate used for registration, in PEM format.  Used to sign
          registration and/or authentication JWTs.
          Will be auto-generated if left blank.
          ),
          type: 'textarea',
          optional: true

    input :udap_cert_iss,
          title: 'JWT Issuer (iss) Claim',
          description: %(
            MUST correspond to a unique URI entry in the Subject Alternative Name (SAN) extension of the client
            certificate used for registration.
            Will be auto-generated with the client cert if left blank.
          ),
          optional: true

    output :udap_cert_iss
    output :udap_client_cert_pem
    output :udap_client_private_key_pem

    run do
      omit_if udap_client_cert_pem.present? && udap_client_private_key_pem.present?,
              'User has opted to provide client certs'

      signing_key = DefaultCertFileLoader.load_default_ca_private_key_file

      cert = UDAPX509Certificate.new(DefaultCertFileLoader.load_default_ca_pem_file, signing_key)

      output udap_cert_iss: cert.san
      output udap_client_cert_pem: cert.cert.to_pem
      output udap_client_private_key_pem: cert.cert_private_key.to_pem
    end
  end
end
