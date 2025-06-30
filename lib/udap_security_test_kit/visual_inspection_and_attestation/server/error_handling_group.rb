require_relative 'error_handling_group/invalid_id_token_test'
require_relative 'error_handling_group/invalid_redirection_uri_test'
require_relative 'error_handling_group/state_mismatch_test'
require_relative 'error_handling_group/unauthenticated_user_test'
require_relative 'error_handling_group/valid_state_error_response_test'

module UDAPSecurityTestKit
  class ErrorHandlingAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_error_handling_group
    title 'Error Handling'

    run_as_group
    test from: :udap_security_invalid_id_token_error
    test from: :udap_security_invalid_redirection_uri
    test from: :udap_security_state_mismatch_error
    test from: :udap_security_unauthenticated_user_error
    test from: :udap_security_valid_state_error_response
  end
end