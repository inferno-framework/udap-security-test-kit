module UDAPSecurityTestKit
  class UDAPAuthExtensionsRequiredFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'udap_authorization_extensions_required field'
    id :udap_auth_extensions_required_field
    description %(
        `udap_authorization_extensions_required field` is an array of zero or more recognized key names for
         Authorization Extension Objects required by the Authorization Server in every token request.
          This metadata parameter SHALL be present if the value of the `udap_authorization_extensions_supported`
           parameter is not an empty array.
      )

    input :udap_well_known_metadata_json

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@30',
                          'hl7.fhir.us.udap-security_1.0.0@31'

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      skip_if !config.key?('udap_authorization_extensions_supported'),
              'Cannot access data needed to assess `udap_authorization_extensions_required` field:
               `udap_authorization_extensions_supported` field is not present'

      skip_if !config['udap_authorization_extensions_supported'].is_a?(Array),
              'Cannot access data needed to assess `udap_authorization_extensions_required` field:
               `udap_authorization_extensions_supported` field is not present'

      omit_if config['udap_authorization_extensions_supported'].blank?, 'No UDAP authorization extensions are supported'

      assert config.key?('udap_authorization_extensions_required'),
             '`udap_authorization_extensions_required` field must be present because
              `udap_authorization_extensions_supported field is not empty'

      assert config['udap_authorization_extensions_required'].is_a?(Array),
             '`udap_authorization_extensions_required` must be an array'
    end
  end
end
