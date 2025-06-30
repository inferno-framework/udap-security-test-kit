require_relative 'server/metadata_server_capabilities_group'
require_relative 'server/dynamic_client_registration_group'
require_relative 'server/authorization_code_token_requests_group'
require_relative 'server/openid_connect_authentication_requests_group'
require_relative 'server/id_token_access_token_validation_group'
require_relative 'server/error_handling_group'
require_relative 'server/security_measures_group'
require_relative 'server/identity_provider_interaction_group'


module UDAPSecurityTestKit
  class ServerAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_visual_inspection_and_attestation
    title 'Visual Inspection and Attestation'

    description <<~DESCRIPTION
      Perform visual inspections or attestations to ensure that the Server is conformant to the UDAP IG requirements.
    DESCRIPTION

    group from: :udap_server_v100_metadata_server_capabilities_group
    group from: :udap_server_v100_dynamic_client_registration_group
    group from: :udap_server_v100_authorization_code_token_requests_group
    group from: :udap_server_v100_openid_connect_authentication_requests_group
    group from: :udap_server_v100_id_token_access_token_validation_group
    group from: :udap_server_v100_error_handling_group
    group from: :udap_server_v100_security_measures_group
    group from: :udap_server_v100_identity_provider_interaction_group
  end
end