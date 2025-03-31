require_relative 'client_access_interaction_test'
require_relative 'client_token_request_verification_test'
require_relative 'client_token_use_verification_test'

module UDAPSecurityTestKit
  class UDAPClientAccess < Inferno::TestGroup
    id :udap_client_access
    title 'Client Access'
    description %(
      During these tests, the client system will access Inferno's simulated
      FHIR server by requesting an access token and making a FHIR request.
      Inferno will then verify that any token requests made were conformant
      and that a token returned from a token request was used on an access request.
    )

    run_as_group

    test from: :udap_client_access_interaction
    test from: :udap_client_token_request_verification
    test from: :udap_client_token_use_verification
  end
end
