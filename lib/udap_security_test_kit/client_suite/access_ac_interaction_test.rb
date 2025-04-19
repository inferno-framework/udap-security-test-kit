require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'client_descriptions'

module UDAPSecurityTestKit
  class UDAPClientAccessAuthorizationCodeInteraction < Inferno::Test
    include URLs
    include ClientWaitDialogDescriptions

    id :udap_client_access_ac_interaction
    title 'Perform UDAP-secured Access'
    description %(
      During this test, Inferno will wait for the client to access data
      using a UDAP token obtained during an earlier test.
    )
    input :client_id,
          title: 'Client Id',
          type: 'text',
          locked: true,
          description: INPUT_CLIENT_ID_DESCRIPTION_LOCKED
    input :launch_context,
          title: 'Launch Context',
          type: 'textarea',
          optional: true,
          description: INPUT_LAUNCH_CONTEXT_DESCRIPTION
    input :fhir_user_relative_reference,
          title: 'FHIR User Relative Reference',
          type: 'text',
          optional: true,
          description: INPUT_FHIR_USER_RELATIVE_REFERENCE
    input :fhir_read_resources_bundle,
          title: 'Available Resources',
          type: 'textarea',
          optional: true,
          description: INPUT_FHIR_READ_RESOURCES_BUNDLE_DESCRIPTION
    input :echoed_fhir_response,
          title: 'Default FHIR Response',
          type: 'textarea',
          optional: true,
          description: INPUT_ECHOED_FHIR_RESPONSE_DESCRIPTION

    run do
      message =
        wait_dialog_authorization_code_access_prefix(client_id, client_fhir_base_url) +
        wait_dialog_access_response_and_continue_suffix(client_id, client_resume_pass_url)

      wait(
        identifier: client_id,
        message:
      )
    end
  end
end
