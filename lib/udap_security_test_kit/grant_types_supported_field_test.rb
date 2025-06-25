require_relative 'common_assertions'

module UDAPSecurityTestKit
  extend CommonAssertions
  class GrantTypesSupportedFieldTest < Inferno::Test
    title 'grant_types_supported field'
    id :udap_grant_types_supported_field
    description %(
        `grant_types_supported` is an array of one or more grant types
      )

    input :udap_well_known_metadata_json
    input :required_flow_type
    output :udap_registration_grant_type

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@36',
                          'hl7.fhir.us.udap-security_1.0.0@37'

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      assert config.key?('grant_types_supported'), '`grant_types_supported` is a required field'

      CommonAssertions.assert_array_of_strings(config, 'grant_types_supported')

      grant_types = config['grant_types_supported']

      assert grant_types.present?, 'Must include at least 1 supported grant type'

      if grant_types.include?('refresh_token')
        assert grant_types.include?('authorization_code'),
               'The `refresh_token` grant type **SHALL** only be included if the `authorization_code` grant type is ' \
               'also included.'
      end

      if required_flow_type.include? 'authorization_code'
        assert grant_types.include?('authorization_code'), 'grant types must
        include authorization_code for this workflow'

        unless required_flow_type.include? 'client_credentials'
          output udap_registration_grant_type: 'authorization_code'
        end
      end

      if required_flow_type.include? 'client_credentials'
        assert grant_types.include?('client_credentials'),
               'grant types must include client_credentials for this workflow'

        unless required_flow_type.include? 'authorization_code'
          output udap_registration_grant_type: 'client_credentials'
        end
      end
    end
  end
end
