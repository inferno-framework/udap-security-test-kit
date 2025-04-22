require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'registration_request_verification'

module UDAPSecurityTestKit
  class UDAPClientRegistrationAuthorizationCodeVerification < Inferno::Test
    include URLs
    include RegistrationRequestVerification

    id :udap_client_registration_ac_verification
    title 'Verify UDAP Authorization Code Registration'
    description %(
        During this test, Inferno will verify that the client's UDAP
        registration request is conformant.
      )
    input :udap_client_uri
    output :udap_registration_jwt

    run do
      client_registration_requests = load_registration_requests_for_client_uri(udap_client_uri)
      skip_if client_registration_requests.empty?,
              "No UDAP Registration Requests made for client uri '#{udap_client_uri}'."

      verify_registration_request(AUTHORIZATION_CODE_TAG, client_registration_requests.last) # most recent if several

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid registration request. See messages for details.'
    end
  end
end
