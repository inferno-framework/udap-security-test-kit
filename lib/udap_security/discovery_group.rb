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
module UDAPSecurity
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

    input_instructions %(
      If Discovery Tests are being not being run as part of a larger OAuth workflow and/or a the server is not required
       to support a specific OAuth flow, select Either for Required OAuth2.0 Flow Type. Otherwise, Discovery Tests will
       verify that the metadata returned by the server supports the designated flow.
    )

    output :udap_registration_certficiations_required
    output :udap_registration_endpoint
    output :udap_registration_grant_type

    run_as_group

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
  end
end
