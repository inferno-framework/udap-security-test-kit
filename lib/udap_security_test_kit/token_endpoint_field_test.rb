module UDAPSecurityTestKit
  class TokenEndpointFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'token_endpoint field'
    id :udap_token_endpoint_field
    description %(
       `token_endpoint` is a string containing the URL of
        the Authorization Server's token endpoint
      )

    input :udap_well_known_metadata_json
    output :udap_token_endpoint

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@10',
                          'hl7.fhir.us.udap-security_1.0.0@40'

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      assert config.key?('token_endpoint'), '`token_endpoint` is a required field'

      endpoint = config['token_endpoint']

      assert endpoint.is_a?(String),
             "`token_endpoint` should be a String, but found #{endpoint.class.name}"
      assert_valid_http_uri(endpoint, "`#{endpoint}` is not a valid URI")

      output udap_token_endpoint: endpoint
    end
  end
end
