require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'client_descriptions'
require_relative 'client_options'
require_relative 'token_verification'

module UDAPSecurityTestKit
  class UDAPClientTokenRequestClientCredentialsVerification < Inferno::Test
    include URLs
    include TokenVerification

    id :udap_client_token_request_cc_verification
    title 'Verify UDAP Client Credentials Token Requests'
    description %(
      Check that UDAP token requests are conformant.
    )

    input :client_id,
          title: 'Client Id',
          type: 'text',
          locked: true,
          description: INPUT_CLIENT_ID_DESCRIPTION_LOCKED
    input :udap_registration_jwt,
          title: 'Registered UDAP Software Statement',
          type: 'textarea',
          locked: 'true',
          description: INPUT_UDAP_REGISTRATION_JWT_DESCRIPTION_LOCKED
    output :udap_tokens

    run do
      load_tagged_requests(TOKEN_TAG, UDAP_TAG, CLIENT_CREDENTIALS_TAG)
      skip_if requests.blank?, 'No UDAP token requests made.'
      # TODO: add refresh requests here and in module TokenVerification

      verify_token_requests(CLIENT_CREDENTIALS_TAG)

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid token requests detected. See messages for details.'
    end
  end
end
