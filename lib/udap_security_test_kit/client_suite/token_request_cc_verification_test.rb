require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'client_descriptions'
require_relative 'client_options'
require_relative 'token_request_verification'

module UDAPSecurityTestKit
  class UDAPClientTokenRequestClientCredentialsVerification < Inferno::Test
    include URLs
    include TokenRequestVerification

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

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@66',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@67'

    def client_suite_id
      return config.options[:endpoint_suite_id] if config.options[:endpoint_suite_id].present?

      UDAPSecurityTestKit::UDAPSecurityClientTestSuite.id
    end

    run do
      load_tagged_requests(TOKEN_TAG, UDAP_TAG, CLIENT_CREDENTIALS_TAG)
      skip_if requests.blank?, 'No UDAP token requests made.'
      load_tagged_requests(TOKEN_TAG, UDAP_TAG, REFRESH_TOKEN_TAG) # verify refresh_requests as well (shouldn't be any)

      verify_token_requests(CLIENT_CREDENTIALS_TAG)

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid token requests received. See messages for details.'
    end
  end
end
