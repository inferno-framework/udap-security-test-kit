require_relative 'access_cc_interaction_test'
require_relative 'token_request_cc_verification_test'
require_relative 'token_use_verification_test'

module UDAPSecurityTestKit
  class UDAPClientAccessClientCredentials < Inferno::TestGroup
    id :udap_client_access_cc
    title 'Client Access'
    description %(
      During these tests, the client system will access Inferno's simulated
      FHIR server by requesting an access token using UDAP's client_credentials flow
      and making a FHIR request presenting the access token. Inferno will then verify
      that any requests made as a part of obtaining the token were conformant and that
      a token returned from a token request was used on an access request.
    )

    run_as_group

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@223'

    test from: :udap_client_access_cc_interaction
    test from: :udap_client_token_request_cc_verification
    test from: :udap_client_token_use_verification
  end
end
