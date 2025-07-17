require_relative 'security_measures_group/csrf_protection_test'
require_relative 'security_measures_group/state_parameter_test'
require_relative 'security_measures_group/obtain_authorization_scopes_test'
require_relative 'security_measures_group/unauthenticated_client_security_test'

module UDAPSecurityTestKit
  class SecurityMeasuresAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_security_measures_group
    title 'Security Measures'

    run_as_group
    test from: :udap_security_csrf_protection
    test from: :udap_security_state_parameter_management
    test from: :udap_security_unauthenticated_clients
    test from: :udap_security_user_authorization
  end
end
