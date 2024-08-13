require_relative 'common_assertions'

module UDAPSecurityTestKit
  extend CommonAssertions
  class RegEndpointJWTSigningAlgValuesSupportedFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'registration_endpoint_jwt_signing_alg_values_supported field'
    id :udap_reg_endpoint_jwt_signing_alg_values_supported_field
    description %(
      If present, `registration_endpoint_jwt_signing_alg_values_supported` is
      an array of one or more strings identifying signature algorithms supported by the Authorization Server for
       validation of signed software statements, certifications, and endorsements
      submitted to the registration endpoint.
    )

    input :udap_well_known_metadata_json

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      omit_if !config.key?('registration_endpoint_jwt_signing_alg_values_supported'),
              '`registration_endpoint_jwt_signing_alg_values_supported` field is recommended but not required'

      CommonAssertions.assert_array_of_strings(config, 'registration_endpoint_jwt_signing_alg_values_supported')
    end
  end
end
