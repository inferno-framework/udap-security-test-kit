require_relative 'client_registration_interaction_test'
require_relative 'client_registration_verification_test'

module UDAPSecurityTestKit
  class UDAPClientRegistration < Inferno::TestGroup
    id :udap_client_registration
    title 'Client Registration'
    description %(
      During these tests, the client system will dynamically register with Inferno's
      simulated UDAP Server with the capabilities to perform the **UDAP B2B client credentials flow**.
      At any time, the client may perform UDAP discovery on the simulated Inferno UDAP server.
    )
    run_as_group

    input :udap_client_uri,
          title: 'UDAP Client URI',
          type: 'text',
          description: %(
            The UDAP Client URI that will be used to register with Inferno's simulated UDAP server.
          ),
          optional: false

    test from: :udap_client_registration_interaction
    test from: :udap_client_registration_verification
  end
end
