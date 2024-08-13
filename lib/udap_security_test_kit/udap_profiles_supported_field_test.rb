require_relative 'common_assertions'

module UDAPSecurityTestKit
  extend CommonAssertions
  class UDAPProfilesSupportedFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'udap_profiles_supported field'
    id :udap_profiles_supported_field
    description %(
        `udap_profiles_supported` is an array of two or more strings identifying the core UDAP profiles supported by the
         Authorization Server. The array SHALL include:
        `udap_dcr` for UDAP Dynamic Client Registration, and
        `udap_authn` for UDAP JWT-Based Client Authentication.
        If the `grant_types_supported` parameter includes the string `client_credentials`, then the array SHALL also
         include:
        `udap_authz` for UDAP Client Authorization Grants using JSON Web Tokens to indicate support for
         Authorization Extension Objects.
      )

    input :udap_well_known_metadata_json

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      assert config.key?('udap_profiles_supported'), '`udap_profiles_supported` is a required field'

      CommonAssertions.assert_array_of_strings(config, 'udap_profiles_supported')

      profiles_supported = config['udap_profiles_supported']

      assert profiles_supported.include?('udap_dcr'),
             'Array must include `udap_dcr` to indicate support for required UDAP Dynamic Client Registration profile'

      assert profiles_supported.include?('udap_authn'),
             'Array must include `udap_authn` value to indicate support for required UDAP JWT-Based Client
              Authentication profile'

      if config['grant_types_supported']&.include?('client_credentials')
        assert profiles_supported.include?('udap_authz'),
               '`client_credentials` grant type is supported, so array must include `udap_authz` to indicate support for
                UDAP Client Authorization Grants using JSON Web Tokens'
      end
    end
  end
end
