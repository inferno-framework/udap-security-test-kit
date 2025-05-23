module UDAPSecurityTestKit
  class UDAPAuthExtensionsSupportedFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'udap_authorization_extensions_supported field'
    id :udap_auth_extensions_supported_field
    description %(
        `udap_authorization_extensions_supported` is an array of zero or more recognized key names for Authorization
         Extension Objects supported by the Authorization Server.
      )

    input :udap_well_known_metadata_json
    input :required_flow_type

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@28',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@29'

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      assert config.key?('udap_authorization_extensions_supported'),
             '`udap_authorization_extensions_supported` is a required field'

      assert config['udap_authorization_extensions_supported'].is_a?(Array),
             '`udap_authorization_extensions_supported` must be an array'

      if required_flow_type.include? 'client_credentials'
        assert config['udap_authorization_extensions_supported'].include?('hl7-b2b'),
               'Must support hl7-b2b authorization extension for client credentials workflow'
      end
    end
  end
end
