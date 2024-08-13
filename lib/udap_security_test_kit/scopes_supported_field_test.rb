require_relative 'common_assertions'

module UDAPSecurityTestKit
  extend CommonAssertions
  class ScopesSupportedFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'scopes_supported field'
    id :udap_scopes_supported_field
    description %(
        If present, `scopes_supported` is an array of one or more
        strings containing scopes
      )

    input :udap_well_known_metadata_json

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      omit_if !config.key?('scopes_supported')

      CommonAssertions.assert_array_of_strings(config, 'scopes_supported')
    end
  end
end
