require 'uri'
module UDAPSecurityTestKit
  class WellKnownEndpointTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'UDAP Well-Known configuration is available'
    id :udap_well_known_endpoint
    description %(
      The [UDAP Discovery IG Section 2.1 Discovery Endpoints](https://hl7.org/fhir/us/udap-security/STU1/discovery.html#discovery-of-endpoints)
      states:
      > Servers SHALL allow access to the following metadata URL to unregistered client applications and without
      > requiring client authentication, where {baseURL} represents the base FHIR URL for the FHIR server:
      > `{baseURL}/.well-known/udap`

      This test ensures the discovery endpoint returns a 200 status and valid JSON body.
    )

    input :udap_fhir_base_url,
          title: 'FHIR Server Base URL',
          description: 'Base FHIR URL of FHIR Server. Discovery request will be sent to {baseURL}/.well-known/udap'

    input :udap_community_parameter,
          title: 'UDAP Community Parameter',
          description: "If included, the designated community value will be appended as a query to the well-known
          endpoint to indicate the client's trust of certificates from this trust community.",
          optional: true

    output :udap_well_known_metadata_json
    makes_request :config

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@12',
                          'hl7.fhir.us.udap-security_1.0.0@13',
                          'hl7.fhir.us.udap-security_1.0.0@14'

    run do
      uri = URI.parse("#{udap_fhir_base_url.strip.chomp('/')}/.well-known/udap")
      unless udap_community_parameter.blank?
        queries = URI.decode_www_form(uri.query || '') << ['community', udap_community_parameter]
        uri.query = URI.encode_www_form(queries)
      end

      get(uri.to_s, name: :udap_well_known_metadata_json)
      assert_response_status(200)
      assert_valid_json(response[:body])
      output udap_well_known_metadata_json: response[:body]
    end
  end
end
