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
      If using auto-generated client certificates, Inferno's default self-signed certificate authority will issue and
      sign the client cert(s). The default Inferno CA can be downloaded as a PEM file at the following link:
      * `#{Inferno::Application[:base_url]}/custom/udap_security/inferno_ca.pem`

      Alternatively, testers may input their own client certificates signed by their own CA. Either way, **the
      authorization server under test MUST be configured to trust the signing certificate** before Dynamic Client
      Registration tests are run.

      Each run of the dynamic client registration tests requires unique
      a unique client cert and private key. To auto-generate a fresh set,
      clear the those inputs prior to re-running.
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
