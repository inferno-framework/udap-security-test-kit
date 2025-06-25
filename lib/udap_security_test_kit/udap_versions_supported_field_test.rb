module UDAPSecurityTestKit
  class UDAPVersionsSupportedFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'udap_versions_supported field'
    id :udap_versions_supported_field
    description %(
        `udap_versions_supported` must contain a fixed array with one string
        element: `["1"]`
      )

    input :udap_well_known_metadata_json

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@22'

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)
      assert config['udap_versions_supported'] == ['1'],
             "`udap_versions_supported` field must contain an array with one string element '1'"
    end
  end
end
