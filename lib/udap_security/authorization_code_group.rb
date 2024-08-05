require_relative 'dynamic_client_registration_group'
require_relative 'discovery_group'
require_relative 'authorization_code_authentication_group'
module UDAPSecurity
  class AuthorizationCodeGroup < Inferno::TestGroup
    title 'UDAP Authorization Code Flow'
    description %(
      This group tests UDAP servers that support JWT authentication using an OAuth2.0 authorization_code grant flow and
       includes the following sub-groups.

      1. Discovery Group
      2. Dynamic Client Registration
      3. Authorization and Authentication - supports both Consumer Facing and Business-to-Buisiness (B2B) profiles in
      the UDAP IG
    )
    id :udap_authorization_code_group

    input_instructions %(
      **Discovery Tests**

      #{DiscoveryGroup.discovery_group_input_instructions}

      **Dynamic Client Registration Tests**

      #{DynamicClientRegistrationGroup.dynamic_client_registration_input_instructions}
    )

    group from: :udap_discovery_group,
          id: :auth_code_discovery_group,
          run_as_group: true,
          config: {
            inputs: {
              required_flow_type: {
                name: :flow_type_auth_code,
                title: 'Required OAuth2.0 Flow Type for Authorization Code Workflow',
                optional: false,
                default: ['authorization_code'],
                locked: true
              }
            }
          }
    group from: :udap_dynamic_client_registration_group,
          id: :auth_code_dcr_group,
          run_as_group: true,
          config: {
            inputs: {
              udap_registration_grant_type: {
                name: :reg_grant_type_auth_code,
                default: 'authorization_code',
                locked: true
              },
              udap_client_cert_pem: {
                name: :udap_client_cert_pem_auth_code_flow
              },
              udap_client_private_key_pem: {
                name: :udap_client_private_key_auth_code_flow
              },
              udap_cert_iss: {
                name: :udap_cert_iss_auth_code_flow
              },
              udap_registration_requested_scope: {
                name: :udap_registration_scope_auth_code_flow
              }
            },
            outputs: {
              udap_client_cert_pem: {
                name: :udap_client_cert_pem_auth_code_flow
              },
              udap_client_private_key_pem: {
                name: :udap_client_private_key_auth_code_flow
              },
              udap_cert_iss: {
                name: :udap_cert_iss_auth_code_flow
              }
            }
          }

    group from: :udap_authorization_code_authentication_group,
          run_as_group: true
  end
end
