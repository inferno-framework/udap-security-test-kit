require_relative 'dynamic_client_registration_group'
require_relative 'discovery_group'
require_relative 'client_credentials_authentication_group'

module UDAPSecurity
  class ClientCredentialsGroup < Inferno::TestGroup
    title 'UDAP Client Credentials Flow'
    description %(
      This group tests UDAP servers that support JWT authentication using an OAuth2.0 client_credentials grant flow and
       includes the following sub-groups.

      1. Discovery Group
      2. Dynamic Client Registration
      3. Authorization and Authentication - supports only Business-to-Business (B2B) UDAP profile
    )
    id :udap_client_credentials_group

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
                name: :flow_type_client_creds,
                title: 'Required OAuth2.0 Flow Type for Client Credentials Workflow',
                optional: 'false',
                default: ['client_credentials'],
                locked: true
              }
            }
          }

    group from: :udap_dynamic_client_registration_group,
          id: :client_creds_dcr_group,
          run_as_group: true,
          config: {
            inputs: {
              udap_registration_grant_type: {
                name: :reg_grant_type_client_creds,
                default: 'client_credentials',
                locked: true
              },
              udap_client_cert_pem: {
                name: :udap_client_cert_pem_client_creds_flow,
                title: 'Client Credentials Client Certificate(s) (PEM Format)'
              },
              udap_client_private_key_pem: {
                name: :udap_client_private_key_client_creds_flow,
                title: 'Client Credentials Client Private Key (PEM Format)'
              },
              udap_cert_iss: {
                name: :udap_cert_iss_client_creds_flow,
                title: 'Client Credentials JWT Issuer (iss) Claim'
              },
              udap_registration_requested_scope: {
                name: :udap_registration_scope_client_creds_flow,
                title: 'Client Credentials Registration Requested Scope(s)',
                description: %(
                  String containing a space delimited list of scopes requested by the client application for use in
                  subsequent requests. The Authorization Server MAY consider this list when deciding the scopes that it
                  will allow the application to subsequently request. Apps requesting the "client_credentials" grant
                  type SHOULD request system scopes.
                )
              },
              udap_registration_certifications: {
                name: :udap_registration_certifications_client_creds_flow,
                title: 'Client Credentials UDAP Registration Certifications'
              }
            },
            outputs: {
              udap_client_cert_pem: {
                name: :udap_client_cert_pem_client_creds_flow
              },
              udap_client_private_key_pem: {
                name: :udap_client_private_key_client_creds_flow
              },
              udap_cert_iss: {
                name: :udap_cert_iss_client_creds_flow
              }
            }
          }

    group from: :udap_client_credentials_authentication_group,
          run_as_group: true

    input_order :udap_fhir_base_url, :flow_type_client_creds,
                :udap_server_trust_anchor_certs,
                :reg_grant_type_client_creds, :udap_client_cert_pem_client_creds_flow,
                :udap_client_private_key_client_creds_flow,
                :udap_cert_iss_client_creds_flow,
                :udap_registration_scope_client_creds_flow,
                :udap_jwt_signing_alg, :udap_registration_certifications
  end
end
