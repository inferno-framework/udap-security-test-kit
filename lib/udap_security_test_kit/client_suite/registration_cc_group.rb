require_relative 'registration_interaction_test'
require_relative 'registration_cc_verification_test'

module UDAPSecurityTestKit
  class UDAPClientRegistrationClientCredentials < Inferno::TestGroup
    id :udap_client_registration_cc
    title 'Client Registration'
    description %(
      During these tests, the client system will dynamically register with Inferno's
      simulated UDAP Server to use the client_credentials flow. At any time, the client
      may perform UDAP discovery on the simulated Inferno UDAP server.
    )
    run_as_group

    test from: :udap_client_registration_interaction
    test from: :udap_client_registration_cc_verification
  end
end
