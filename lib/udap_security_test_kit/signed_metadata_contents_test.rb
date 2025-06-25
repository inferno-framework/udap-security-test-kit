require 'jwt'
require_relative 'udap_jwt_validator'
module UDAPSecurityTestKit
  class SignedMetadataContentsTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'signed_metadata contents'
    id :udap_signed_metadata_contents
    description %(
      `signed_metadata` is a string containing a JWT listing the server's endpoints.  This test will validate the JWT
      signature as specified in [UDAP IG Section 1.2 JSON Web Token (JWT) Requirements](https://hl7.org/fhir/us/udap-security/STU1/index.html#json-web-token-jwt-requirements)
      and validate the JWT contents as outlined in [UDAP Discovery IG Section 2.3 Signed Metadata Elements](https://hl7.org/fhir/us/udap-security/STU1/discovery.html#signed-metadata-elements).
    )

    input :signed_metadata_jwt, optional: true
    input :udap_well_known_metadata_json, :udap_fhir_base_url

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@1',
                          'hl7.fhir.us.udap-security_1.0.0@2',
                          'hl7.fhir.us.udap-security_1.0.0@3',
                          'hl7.fhir.us.udap-security_1.0.0@7',
                          'hl7.fhir.us.udap-security_1.0.0@8',
                          'hl7.fhir.us.udap-security_1.0.0@48',
                          'hl7.fhir.us.udap-security_1.0.0@49',
                          'hl7.fhir.us.udap-security_1.0.0@50',
                          'hl7.fhir.us.udap-security_1.0.0@51',
                          'hl7.fhir.us.udap-security_1.0.0@52',
                          'hl7.fhir.us.udap-security_1.0.0@53',
                          'hl7.fhir.us.udap-security_1.0.0@54',
                          'hl7.fhir.us.udap-security_1.0.0@55',
                          'hl7.fhir.us.udap-security_1.0.0@57',
                          'hl7.fhir.us.udap-security_1.0.0@58',
                          'hl7.fhir.us.udap-security_1.0.0@59'

    run do
      skip_if signed_metadata_jwt.blank?

      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      token_body, token_header = JWT.decode(signed_metadata_jwt, nil, false)

      assert token_header.key?('x5c'), 'JWT header does not contain `x5c` field'
      assert token_header.key?('alg'), 'JWT header does not contain `alg` field'

      leaf_cert_der = Base64.decode64(token_header['x5c'].first)
      leaf_cert = OpenSSL::X509::Certificate.new(leaf_cert_der)
      signature_validation_result = UDAPSecurityTestKit::UDAPJWTValidator.validate_signature(
        signed_metadata_jwt,
        token_header['alg'],
        leaf_cert
      )

      assert signature_validation_result[:success], signature_validation_result[:error_message]

      ['iss', 'sub', 'exp', 'iat', 'jti'].each do |key|
        assert token_body.key?(key), "JWT does not contain `#{key}` claim"
      end

      ['token_endpoint', 'registration_endpoint']
        .each do |key|
          assert token_body.key?(key), "JWT must contain `#{key}` claim"
          assert token_body[key].is_a?(String), "Value for `#{key}` must be a String"
        end

      if config.key?('authorization_endpoint')
        assert token_body.key?('authorization_endpoint'),
               'JWT must contain `authorization_endpoint` key because it is present in unsigned metadata'
        assert token_body['authorization_endpoint'].is_a?(String), 'Value for `authorization_endpoint` must be a String'

        assert token_body['iss'] == udap_fhir_base_url,
               "`iss` claim `#{token_body['iss']}` is not the same as server base url `#{udap_fhir_base_url}`"

        begin
          alt_names =
            leaf_cert.extensions
              .find { |extension| extension.oid == 'subjectAltName' }
              .value
        rescue NoMethodError
          assert false, 'Could not find Subject Alternative Name extension in leaf certificate'
        end

        # Certification may have more than one SAN value
        assert alt_names.include?("URI:#{token_body['iss']}"),
               "`iss` claim `#{token_body['iss']}` not found in Subject Alternative Name extension " \
               "from the `x5c` JWT header: `#{alt_names}`"

        assert token_body['iss'] == token_body['sub'],
               "`iss` claim `#{token_body['iss']}` does not match `sub` claim `#{token_body['sub']}`"

        ['iat', 'exp'].each do |key|
          assert token_body[key].is_a?(Numeric),
                 "Expected `#{key}` to be numeric, but found #{token_body[key].class.name}"
        end
        issue_time = Time.at(token_body['iat'])
        expiration_time = Time.at(token_body['exp'])

        assert expiration_time <= issue_time + 1.year, %(
        `exp` is more than a year after `iat`'.
        * `iat`: #{token_body['iat']} - #{issue_time.iso8601}
        * `exp`: #{token_body['exp']} - #{expiration_time.iso8601}
      )
      end
    end
  end
end
