module UDAPSecurityTestKit
  class AuthorizationEndpointFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'authorization_endpoint field'
    id :udap_authorization_endpoint_field
    description %(
        `authorization_endpoint` is a string containing the absolute URL of the Authorization Server's authorization
        endpoint. This parameter SHALL be present if the value of the
        grant_types_supported parameter includes the string "authorization_code"
      )

    input :udap_well_known_metadata_json
    output :udap_authorization_endpoint

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      skip_if !config.key?('grant_types_supported'),
              'Cannot access data needed to assess `authorization_endpoint` field:
               `grant_types_supported` field not present'

      skip_if !config['grant_types_supported'].is_a?(Array),
              'Cannot access data needed to assess `authorization_endpoint` field: `grant_types_supported` field is not
               correctly formatted'

      omit_if !config['grant_types_supported'].include?('authorization_code'),
              '`authorization_endpoint` field is only required if `authorization_code` is a supported grant type'

      assert config.key?('authorization_endpoint'),
             '`authorization_endpoint` field is required if `authorization_endpoint` is a supported grant type'

      endpoint = config['authorization_endpoint']

      assert endpoint.is_a?(String),
             "`authorization_endpoint` should be a String, but found #{endpoint.class.name}"
      assert_valid_http_uri(endpoint, "`#{endpoint}` is not a valid URI")

      output udap_authorization_endpoint: endpoint
    end
  end
end
