require 'jwt'
require_relative 'udap_jwt_validator'
module UDAPSecurity
  class SignedMetadataTrustVerificationTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'signed_metadata contents: trust can be verified from server certificates'
    id :udap_signed_metadata_trust_verification
    description %(
       The UDAP IG profile on UDAP Server Metadata Section 3.2 says:
       > The Client app attempts to construct a valid certificate chain from the Server’s certificate (cert1) to an
       > anchor certificate trusted by the Client app using conventional X.509 chain building techniques and path
       > validation, including certificate validity and revocation status checking. The Server MAY provide a complete
       > certificate chain in the x5c element. The Client app MAY use additional certificates not included by the Server
       > to construct a chain.

       This test will establish trust against the root CA(s) provided as test inputs.
       Currently, the use of Authority Information Access (AIA) extensions is NOT supported.  As such, servers must
       include any intermediate CAs necessary for building a trust chain in the JWT `x5c` header OR as an additional
       trust anchor certificate input to the test (see input instructions for more details).
      )

    input :signed_metadata_jwt
    input :udap_server_trust_anchor_certs,
          title: 'Auth Server Trust Anchor X509 Certificate(s) (PEM Format)',
          description: %(
            A comma-separated list of one or more trust anchor root CA X.509 certificates Inferno will use to establish
            trust with the authorization server's certificates provided in the discovery response signed_metadata JWT.
          ),
          type: 'textarea'

    run do
      _token_body, token_header = JWT.decode(signed_metadata_jwt, nil, false)

      assert token_header.key?('x5c'), 'JWT header does not contain `x5c` field'
      assert token_header.key?('alg'), 'JWT header does not contain `alg` field'

      anchor_certs_parsed = udap_server_trust_anchor_certs.split(',')
      trust_anchor_certs = anchor_certs_parsed.map do |cert_pem|
        OpenSSL::X509::Certificate.new(cert_pem)
      end

      trust_chain_valid, error_message = UDAPJWTValidator.validate_trust_chain(
        token_header['x5c'],
        trust_anchor_certs
      )

      assert trust_chain_valid,
             "Trust could not be established with server certificates, error message: #{error_message}"
    end
  end
end
