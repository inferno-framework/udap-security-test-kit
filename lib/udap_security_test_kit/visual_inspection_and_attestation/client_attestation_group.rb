require_relative 'client/authorization_code_usage_test'
require_relative 'client/b2b_authorization_extension_object_test'
require_relative 'client/client_security_csrf_protection_test'
require_relative 'client/idp_supports_required_scopes_test'
require_relative 'client/jti_reuse_prevention_test'
require_relative 'client/metadata_interpretation_test'
require_relative 'client/preferred_identity_provider_test'
require_relative 'client/private_key_authentication_test'
require_relative 'client/scopes_identity_provider_interaction_test'
require_relative 'client/software_statement_registration_test'
require_relative 'client/token_request_authentication_test'
require_relative 'client/trust_community_query_parameters_test'
require_relative 'client/validation_confidentiality_test'

module UDAPSecurityTestKit
  class ClientAttestationGroup < Inferno::TestGroup
    id :udap_client_v100_visual_inspection_and_attestation
    title 'Visual Inspection and Attestation'

    description <<~DESCRIPTION
      Perform visual inspections or attestations to ensure that the Client is conformant to the UDAP IG requirements.
    DESCRIPTION

    run_as_group
    test from: :udap_security_client_auth_code_usage
    test from: :udap_security_idp_supports_scopes
    test from: :udap_security_jti_reuse_prevention
    test from: :udap_security_metadata_interpretation
    test from: :udap_security_preferred_idp
    test from: :udap_security_private_key_authentication
    test from: :udap_security_token_request_authentication
    test from: :udap_security_software_statement_registration
    test from: :udap_security_b2b_authorization_extension_object
    test from: :udap_security_client_security_csrf_protection
    test from: :udap_security_scopes_identity_provider_interaction
    test from: :udap_security_validation_confidentiality
    test from: :udap_security_trust_community_query_parameters
  end
end