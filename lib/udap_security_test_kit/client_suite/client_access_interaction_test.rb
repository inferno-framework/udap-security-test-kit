require_relative '../urls'
require_relative '../endpoints/mock_udap_server'

module UDAPSecurityTestKit
  class UDAPClientAccessInteraction < Inferno::Test
    include URLs

    id :udap_client_access_interaction
    title 'Perform UDAP-secured Access'
    description %(
      During this test, Inferno will wait for the client to access data
      using a UDAP token obtained
    )
    input :client_id,
          optional: true
    input :echoed_fhir_response

    run do
      omit_if client_id.blank?,
              'Not configured for UDAP authentication.'

      wait(
        identifier: client_id,
        message: %(
            **Access**

            Use the registered client id (#{client_id}) to obtain an access
            token using the B2B client credentials flow and use that token
            to access a FHIR endpoint under the simulated server's base URL

            #{fhir_base_url}`

            Inferno will echo the response provided in the **FHIR Response to Echo** input.

            [Click here](#{resume_pass_url}?token=#{client_id}) once you performed
            the access.
          )
      )
    end
  end
end
