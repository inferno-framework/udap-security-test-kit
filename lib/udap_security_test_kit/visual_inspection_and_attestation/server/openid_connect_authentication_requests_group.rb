require_relative 'openid_connect_authentication_requests_group/authentication_request_construction_test'
require_relative 'openid_connect_authentication_requests_group/authentication_request_validation_test'

module UDAPSecurityTestKit
  class OpenIDConnectAuthenticationRequestsAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_openid_connect_authentication_requests_group
    title 'OpenID Connect Authentication Requests'

    run_as_group
    test from: :oidc_auth_request_construction
    test from: :udap_security_access_token_request_validation
  end
end