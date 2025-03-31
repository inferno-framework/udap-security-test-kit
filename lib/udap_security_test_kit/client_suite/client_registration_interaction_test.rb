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
          optional: true

    output :client_id

    run do
      omit_if udap_client_uri.blank?,
              'Not configured for UDAP authentication.'

      generated_client_id = MockUdapServer.client_uri_to_client_id(udap_client_uri)
      output client_id: generated_client_id

      wait(
        identifier: generated_client_id,
        message: %(
            **UDAP Registration**

            Make a UDAP dyanmic registration request for Client URI

            `#{udap_client_uri}`

            To the UDAP-protected FHIR Server at

            `#{fhir_base_url}`

            Metadata on Inferno's simulated UDAP server can be found at

            `#{udap_discovery_url}`

            [Click here](#{resume_pass_url}?token=#{generated_client_id}) once you have
            succesfully completed the registration.
          )
      )
    end
  end
end
