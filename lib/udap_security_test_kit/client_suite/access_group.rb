require_relative 'access_ac_interaction_test'
require_relative 'access_cc_interaction_test'
require_relative 'authorization_request_verification_test'
require_relative 'token_request_ac_verification_test'
require_relative 'token_request_cc_verification_test'
require_relative 'token_use_verification_test'

module UDAPSecurityTestKit
  class UDAPClientAccess < Inferno::TestGroup
    id :udap_client_access
    title 'Client Access'
    description %(
      During these tests, the client system will access Inferno's simulated
      FHIR server by requesting an access token using UDAP and making a FHIR
      request presenting the access token. Inferno will then verify that any requests
      made as a part of obtaining the token were conformant and that a token returned
      from a token request was used on an access request.
    )

    run_as_group

    test from: :udap_client_access_ac_interaction,
         required_suite_options: {
           client_type: UDAPClientOptions::UDAP_AUTHORIZATION_CODE
         }
    test from: :udap_client_access_cc_interaction,
         required_suite_options: {
           client_type: UDAPClientOptions::UDAP_CLIENT_CREDENTIALS
         }
    # Authorization Request Verification (authorization code only)
    test from: :udap_client_authorization_request_verification,
         required_suite_options: {
           client_type: UDAPClientOptions::UDAP_AUTHORIZATION_CODE
         }
    test from: :udap_client_token_request_ac_verification,
         required_suite_options: {
           client_type: UDAPClientOptions::UDAP_AUTHORIZATION_CODE
         }
    test from: :udap_client_token_request_cc_verification,
         required_suite_options: {
           client_type: UDAPClientOptions::UDAP_CLIENT_CREDENTIALS
         }
    test from: :udap_client_token_use_verification
  end
end
