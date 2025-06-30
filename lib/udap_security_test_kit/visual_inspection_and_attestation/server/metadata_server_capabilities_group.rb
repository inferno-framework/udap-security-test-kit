require_relative 'metadata_server_capabilities_group/udap_authorization_extensions_required_test'
require_relative 'metadata_server_capabilities_group/udap_community_parameter_support_test'
require_relative 'metadata_server_capabilities_group/udap_metadata_endpoint_error_handling_test'
require_relative 'metadata_server_capabilities_group/udap_metadata_representation_test'
require_relative 'metadata_server_capabilities_group/udap_profiles_supported_test'

module UDAPSecurityTestKit
  class MetadataServerCapabilitiesAttestationGroup < Inferno::TestGroup
    id :udap_server_v100_metadata_server_capabilities_group
    title 'UDAP Metadata and Server Capabilities'

    run_as_group
    test from: :udap_security_authorization_extensions_required
    test from: :udap_security_community_parameter_support
    test from: :udap_security_metadata_error_handling
    test from: :udap_security_metadata_representation
    test from: :udap_security_profiles_supported
  end
end