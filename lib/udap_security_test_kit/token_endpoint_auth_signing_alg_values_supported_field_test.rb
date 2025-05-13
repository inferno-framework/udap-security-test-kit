require_relative 'common_assertions'

module UDAPSecurityTestKit
  extend CommonAssertions
  class TokenEndpointAuthSigningAlgValuesSupportedFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'token_endpoint_auth_signing_alg_values_supported field'
    id :udap_token_endpoint_auth_signing_alg_values_supported_field
    description %(
       `token_endpoint_auth_signing_alg_values_supported` is an
        array of one or more strings identifying signature algorithms supported by the Authorization Server for
         validation of signed JWTs submitted to the token endpoint for client authentication.
      )

    input :udap_well_known_metadata_json

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@42'

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      assert config.key?('token_endpoint_auth_signing_alg_values_supported'),
             '`token_endpoint_auth_signing_alg_values_supported` is a required field'

      CommonAssertions.assert_array_of_strings(config, 'token_endpoint_auth_signing_alg_values_supported')

      algs_supported = config['token_endpoint_auth_signing_alg_values_supported']

      assert algs_supported.present?, 'Must support at least one signature algorithm'

      assert algs_supported.include?('RS256'), 'All UDAP implementations must support RS256 signature algorithm'
    end
  end
end
