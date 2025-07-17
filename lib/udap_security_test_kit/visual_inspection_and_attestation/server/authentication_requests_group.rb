require_relative 'authentication_requests_group/authentication_request_construction_test'
require_relative 'authentication_requests_group/authentication_request_validation_test'

module UDAPSecurityTestKit
  class OpenIDConnectAuthenticationRequestsAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_authentication_requests_group
    title 'Authentication Requests'

    run_as_group
    test from: :oidc_auth_request_construction
    test from: :oidc_auth_request_validation
  end
end
