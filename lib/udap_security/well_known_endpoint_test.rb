module UDAPSecurity
  class WellKnownEndpointTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'UDAP Well-Known configuration is available'
    id :udap_well_known_endpoint
    description %(
      The metadata returned from `{baseURL}/.well-known/udap` **SHALL**
      represent the server’s capabilities with respect to the UDAP workflows
      described in this guide.
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
