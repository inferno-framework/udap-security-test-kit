require_relative 'common_assertions'
module UDAPSecurity
  extend CommonAssertions
  class UDAPCertificationsSupportedFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'udap_certifications_supported field'
    id :udap_certifications_supported_field
    description %(
        `udap_certifications_supported` is an array of zero or more
        certification URIs
      )

    input :udap_well_known_metadata_json

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      assert config.key?('udap_certifications_supported'), '`udap_certifications_supported` is a required field'

      CommonAssertions.assert_array_of_strings(config, 'udap_certifications_supported')

      non_uri_values =
        config['udap_certifications_supported']
          .grep_v(URI::DEFAULT_PARSER.make_regexp)

      error_message = '`udap_certifacations_supported` should be an Array of URI strings, but found
       #{non_uri_values.map(&:class).map(&:name).join(', ')}'
      assert non_uri_values.blank?, error_message
    end
  end
end
