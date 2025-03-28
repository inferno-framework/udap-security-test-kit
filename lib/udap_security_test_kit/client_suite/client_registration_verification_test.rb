require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'

module UDAPSecurityTestKit
  class UDAPClientRegistrationVerification < Inferno::Test
    include URLs

    id :udap_client_registration_verification
    title 'Verify UDAP Registration'
    description %(
        During this test, Inferno will verify that the client's UDAP
        registration request is conformant.
      )
    input :udap_client_uri,
          optional: true

    run do
      omit_if udap_client_uri.blank?,
              'Not configured for UDAP authentication.'

      load_tagged_requests(UDAP_TAG, REGISTRATION_TAG)

      skip_if requests.empty?, 'No UDAP Registration Requests made.'

      verified_request = requests.last

      # TODO: - implement more stuff in here
      parsed_body = MockUdapServer.parsed_request_body(verified_request)
      ss_claims = MockUdapServer.jwt_claims(parsed_body&.dig('software_statement'))
      assert ss_claims&.dig('aud') == registration_url,
             "`aud` expected to be '#{registration_url}', got '#{ss_claims&.dig('aud')}'"
    end
  end
end
