require_relative 'registration_interaction_test'
require_relative 'registration_verification_test'

module UDAPSecurityTestKit
  class UDAPClientRegistration < Inferno::TestGroup
    id :udap_client_registration
    title 'Client Registration'
    description %(
      During these tests, the client system will dynamically register with Inferno's
      simulated UDAP Server. At any time, the client may perform UDAP discovery on the
      simulated Inferno UDAP server.
    )
    run_as_group

    test from: :udap_client_registration_interaction
    test from: :udap_client_registration_verification
  end
end
