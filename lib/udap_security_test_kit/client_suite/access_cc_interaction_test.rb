require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'client_descriptions'

module UDAPSecurityTestKit
  class UDAPClientAccessClientCredentialsInteraction < Inferno::Test
    include URLs
    include ClientWaitDialogDescriptions

    id :udap_client_access_cc_interaction
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

    def client_suite_id
      return config.options[:endpoint_suite_id] if config.options[:endpoint_suite_id].present?

      UDAPSecurityTestKit::UDAPSecurityClientTestSuite.id
    end

    run do
      message =
        wait_dialog_client_credentials_access_prefix(client_id, client_fhir_base_url) +
        wait_dialog_access_response_and_continue_suffix(client_id, client_resume_pass_url)

      wait(
        identifier: client_id,
        message:
      )
    end
  end
end
