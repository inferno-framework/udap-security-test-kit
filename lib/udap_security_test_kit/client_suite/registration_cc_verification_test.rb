require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'registration_request_verification'

module UDAPSecurityTestKit
  class UDAPClientRegistrationClientCredentialsVerification < Inferno::Test
    include URLs
    include RegistrationRequestVerification

    id :udap_client_registration_cc_verification
    title 'Verify UDAP Client Credentials Registration'
    description %(
        During this test, Inferno will verify that the client's UDAP
        registration request is conformant.
      )
    input :udap_client_uri
    output :udap_registration_jwt

    def client_suite_id
      return config.options[:endpoint_suite_id] if config.options[:endpoint_suite_id].present?

      UDAPSecurityTestKit::UDAPSecurityClientTestSuite.id
    end

    run do
      client_registration_requests = load_registration_requests_for_client_uri(udap_client_uri)
      skip_if client_registration_requests.empty?,
              "No UDAP Registration Requests made for client uri '#{udap_client_uri}'."

      verify_registration_request(CLIENT_CREDENTIALS_TAG, client_registration_requests.last) # most recent if several

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid registration request. See messages for details.'
    end
  end
end
