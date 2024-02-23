module UDAPSecurity
  class TokenEndpointAuthMethodsSupportedFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'token_endpoint_auth_methods_supported field'
    id :udap_token_endpoint_auth_methods_supported_field
    description %(
      `token_endpoint_auth_methods_supported` must contain a fixed
      array with one string element: `["private_key_jwt"]`
    )
    input :udap_well_known_metadata_json

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      assert config['token_endpoint_auth_methods_supported'] == ['private_key_jwt'],
             '`token_endpoint_auth_methods_supported` field must contain an array ' \
             "with one string element 'private_key_jwt'"
    end
  end
end
