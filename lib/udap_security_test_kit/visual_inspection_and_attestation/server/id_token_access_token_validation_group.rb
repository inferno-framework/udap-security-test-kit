require_relative 'id_token_access_token_validation_group/id_token_validation_test'
require_relative 'id_token_access_token_validation_group/access_token_validation_test'
require_relative 'id_token_access_token_validation_group/token_response_validation_test'



module UDAPSecurityTestKit
  class IDTokenAccessTokenValidationAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_id_token_access_token_validation_group
    title 'ID Token and Access Token Validation'

    run_as_group
    test from: :udap_security_id_token_validation
    test from: :udap_security_access_token_validation
    test from: :udap_security_token_response_validation

  end
end