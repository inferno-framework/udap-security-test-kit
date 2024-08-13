require 'jwt'
require_relative 'authorization_endpoint_field_test'
require_relative 'grant_types_supported_field_test'
require_relative 'reg_endpoint_jwt_signing_alg_values_supported_field_test'
require_relative 'registration_endpoint_field_test'
require_relative 'scopes_supported_field_test'
require_relative 'signed_metadata_contents_test'
require_relative 'signed_metadata_field_test'
require_relative 'token_endpoint_auth_methods_supported_field_test'
require_relative 'token_endpoint_auth_signing_alg_values_supported_field_test'
require_relative 'token_endpoint_field_test'
require_relative 'udap_auth_extensions_required_field_test'
require_relative 'udap_auth_extensions_supported_field_test'
require_relative 'udap_certifications_required_field_test'
require_relative 'udap_certifications_supported_field_test'
require_relative 'udap_profiles_supported_field_test'
require_relative 'udap_versions_supported_field_test'
require_relative 'well_known_endpoint_test'
require_relative 'signed_metadata_trust_verification_test'
module UDAPSecurityTestKit
  class DiscoveryGroup < Inferno::TestGroup
    include Inferno::DSL::Assertions

    title 'UDAP Discovery'
    description %(
      Verify that server configuration is made available and conforms with [the
      discovery
      requirements](https://hl7.org/fhir/us/udap-security/STU1/discovery.html).
    )
    id :udap_discovery_group

    input :required_flow_type,
          title: 'Required Supported OAuth2.0 Grant Type(s)',
          description: 'Which grant type(s) must be supported per the returned Discovery metadata',
          type: 'checkbox',
          optional: 'true',
          options: {
            list_options: [
              {
                label: 'Authorization Code',
                value: 'authorization_code'
              },
              {
                label: 'Client Credentials',
                value: 'client_credentials'
              }
            ]
          }

    def self.discovery_group_input_instructions
      %(
      Inferno currently does not support the use of the Authority Information Access (AIA) extension to access issuing
      certificates.  As such, Inferno must be provided any intermediate server certificates needed to establish a
      trust chain.  If the intermediate CAs are not included in the x5c header of the server's signed metadata JWT,
      testers may include them along with the root CA as a trust anchor input.
    )
    end
    input_instructions discovery_group_input_instructions

    output :udap_registration_certficiations_required
    output :udap_registration_endpoint
    output :udap_registration_grant_type

    test from: :udap_well_known_endpoint
    test from: :udap_versions_supported_field
    test from: :udap_grant_types_supported_field
    test from: :udap_profiles_supported_field
    test from: :udap_auth_extensions_supported_field
    test from: :udap_auth_extensions_required_field
    test from: :udap_certifications_supported_field
    test from: :udap_certifications_required_field
    test from: :udap_scopes_supported_field
    test from: :udap_authorization_endpoint_field
    test from: :udap_token_endpoint_field
    test from: :udap_token_endpoint_auth_methods_supported_field
    test from: :udap_token_endpoint_auth_signing_alg_values_supported_field
    test from: :udap_registration_endpoint_field
    test from: :udap_reg_endpoint_jwt_signing_alg_values_supported_field
    test from: :udap_signed_metadata_field
    test from: :udap_signed_metadata_contents
    test from: :udap_signed_metadata_trust_verification, optional: true,
         config: {
           inputs: {
             udap_server_trust_anchor_certs: {
               optional: true
             }
           }
         }
  end
end
