require_relative 'access_ac_interaction_test'
require_relative 'authorization_request_verification_test'
require_relative 'token_request_ac_verification_test'
require_relative 'token_use_verification_test'

module UDAPSecurityTestKit
  class UDAPClientAccessAuthorizationCode < Inferno::TestGroup
    id :udap_client_access_ac
    title 'Client Access'
    description %(
      During these tests, the client system will access Inferno's simulated
      FHIR server by requesting an access token using UDAP's authorization_code flow
      and making a FHIR request presenting the access token. Inferno will then verify
      that any requests made as a part of obtaining the token were conformant and that
      a token returned from a token request was used on an access request.
    )

    run_as_group

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@126'

    test from: :udap_client_access_ac_interaction
    test from: :udap_client_authorization_request_verification
    test from: :udap_client_token_request_ac_verification
    test from: :udap_client_token_use_verification
  end
end
