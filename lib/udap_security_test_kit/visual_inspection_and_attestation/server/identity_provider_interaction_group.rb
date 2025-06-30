require_relative 'identity_provider_interaction_group/idp_authentication_request_test'
require_relative 'identity_provider_interaction_group/idp_dynamic_registration_test'
require_relative 'identity_provider_interaction_group/idp_metadata_validation_test'
require_relative 'identity_provider_interaction_group/idp_token_exchange_test'

module UDAPSecurityTestKit
  class IdentityProviderInteractionAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_identity_provider_interaction_group
    title 'Interaction with Identity Providers (IdPs)'

    run_as_group
    test from: :udap_security_idp_metadata_validation
    test from: :udap_security_idp_dynamic_registration
    test from: :udap_security_idp_authentication_request
    test from: :udap_security_idp_token_exchange
  end
end