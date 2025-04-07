require_relative '../urls'
require_relative '../endpoints/mock_udap_server'

module UDAPSecurityTestKit
  class UDAPClientRegistrationInteraction < Inferno::Test
    include URLs

    id :udap_client_registration_interaction
    title 'Perform UDAP Registration'
    description %(
        During this test, Inferno will wait for the client to register
        themselves as a UDAP client with Inferno's simulated UDAP server
        using UDAP dynamic registration.
      )
    input :udap_client_uri,
          optional: false

    output :client_id

    run do
      omit_if udap_client_uri.blank?, # for re-use: mark the udap_client_uri input as optional when importing to enable
              'Not configured for UDAP authentication.'

      generated_client_id = MockUDAPServer.client_uri_to_client_id(udap_client_uri)
      output client_id: generated_client_id

      wait(
        identifier: generated_client_id,
        message: %(
            **UDAP Registration**

            Make a UDAP dyanmic registration request to the UDAP-protected FHIR Server at

            `#{client_fhir_base_url}`

            For Client URI

            `#{udap_client_uri}`

            Metadata on Inferno's simulated UDAP server can be found at

            `#{client_udap_discovery_url}`

            [Click here](#{client_resume_pass_url}?token=#{generated_client_id}) once you have
            succesfully completed the registration.
          )
      )
    end
  end
end
