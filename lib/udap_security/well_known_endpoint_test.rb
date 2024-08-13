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

    output :udap_well_known_metadata_json
    makes_request :config

    run do
      get("#{udap_fhir_base_url.strip.chomp('/')}/.well-known/udap", name: :udap_well_known_metadata_json)
      assert_response_status(200)
      assert_valid_json(response[:body])
      output udap_well_known_metadata_json: response[:body]
    end
  end
end
