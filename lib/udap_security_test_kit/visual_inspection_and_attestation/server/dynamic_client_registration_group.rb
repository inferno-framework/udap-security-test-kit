require_relative 'dynamic_client_registration_group/certification_handling_test'
require_relative 'dynamic_client_registration_group/client_id_modification_test'
require_relative 'dynamic_client_registration_group/dynamic_client_registration_validation_test'

module UDAPSecurityTestKit
  class DynamicClientRegistrationAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_dynamic_client_registration_group
    title 'Dynamic Client Registration'

    run_as_group
    test from: :udap_security_dynamic_client_registration_validation
    test from: :udap_security_certification_handling
    test from: :udap_security_client_id_modification
  end
end