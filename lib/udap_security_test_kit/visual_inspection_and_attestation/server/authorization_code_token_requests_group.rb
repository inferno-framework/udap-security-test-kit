require_relative 'authorization_code_token_requests_group/authorization_code_usage_test'
require_relative 'authorization_code_token_requests_group/access_token_request_validation_test'
require_relative 'authorization_code_token_requests_group/access_token_lifetime_test'

module UDAPSecurityTestKit
  class AuthorizationCodeTokenRequestsAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_authorization_code_token_requests_group
    title 'Authorization Code and Token Requests'

    run_as_group
    test from: :udap_security_auth_code_usage
    test from: :udap_security_access_token_request_validation
    test from: :udap_security_access_token_lifetime
  end
end