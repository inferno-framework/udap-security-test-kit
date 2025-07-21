require_relative 'jwt_security_group/jwt_certificate_chain_validation_test'
require_relative 'jwt_security_group/jwt_grant_parameter_validation_test'
require_relative 'jwt_security_group/jwt_jti_reuse_test'
require_relative 'jwt_security_group/jwt_signature_validation_test'
require_relative 'jwt_security_group/jwt_token_request_validation_test'

module UDAPSecurityTestKit
  class JWTSecurityGroup < Inferno::TestGroup
    id :udap_server_v100_jwt_security_group
    title 'JWT/Token Validation and Security'

    run_as_group
    test from: :udap_security_jwt_token_request_validation
    test from: :udap_security_jwt_signature_validation
    test from: :udap_security_jwt_jti_reuse
    test from: :udap_security_jwt_grant_parameter_validation
    test from: :udap_security_jwt_certificate_chain_validation
  end
end
