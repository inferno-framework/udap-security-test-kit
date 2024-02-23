require_relative 'common_assertions'

module UDAPSecurity
  extend CommonAssertions
  class UDAPCertificationsRequiredFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'udap_certifications_required field'
    id :udap_certifications_required_field
    description %(
        If `udap_certifications_supported` is not empty, then `udap_certifications_required` is an array of zero or more
        certification URIs
      )

    input :udap_well_known_metadata_json
    output :udap_certifications_required

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      skip_if !config.key?('udap_certifications_supported'),
              'Assessment of `udap_certifications_required` field is dependent on values in
               `udap_certifications_supported`field, which is not present'

      omit_if config['udap_certifications_supported'].blank?, 'No UDAP certifications are supported'

      CommonAssertions.assert_array_of_strings(config, 'udap_certifications_required')

      if config['udap_certifications_required'].blank?
        output udap_certifications_required: 'false'
      else
        output udap_certifications_required: 'true'
      end

      non_uri_values =
        config['udap_certifications_required']
          .grep_v(URI::DEFAULT_PARSER.make_regexp)

      assert non_uri_values.blank?,
             '`udap_certifacations_required` should be an Array of ' \
             "URI strings but found #{non_uri_values.map(&:class).map(&:name).join(', ')}"
    end
  end
end
