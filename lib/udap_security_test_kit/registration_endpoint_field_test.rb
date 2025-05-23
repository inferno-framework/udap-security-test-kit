module UDAPSecurityTestKit
  class RegistrationEndpointFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'registration_endpoint field'
    id :udap_registration_endpoint_field
    description %(
        `registration_endpoint` is a string containing the URL of
        the Authorization Server's registration endpoint
      )

    input :udap_well_known_metadata_json
    output :udap_registration_endpoint

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@11',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@43'

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      assert config.key?('registration_endpoint'), '`registration_endpoint` is a required field'

      endpoint = config['registration_endpoint']

      assert endpoint.is_a?(String),
             "`registration_endpoint` should be a String, but found #{endpoint.class.name}"
      assert_valid_http_uri(endpoint, "`#{endpoint}` is not a valid URI")

      output udap_registration_endpoint: endpoint
    end
  end
end
