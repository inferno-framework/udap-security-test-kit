require_relative 'dynamic_client_registration_group'
require_relative 'discovery_group'
require_relative 'client_credentials_authentication_group'

module UDAPSecurityTestKit
  class ClientCredentialsGroup < Inferno::TestGroup
    title 'UDAP Client Credentials Flow'
    description %(
      This group tests UDAP servers that support JWT authentication using an OAuth2.0 client_credentials grant flow and
       includes the following sub-groups.

      1. Discovery Group
      2. Dynamic Client Registration
      3. Authorization and Authentication - supports only the [Business-to-Business (B2B)](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)
      profile in the UDAP IG
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
                name: :udap_client_credentials_flow_registration_grant_type,
                default: 'client_credentials',
                locked: true
              },
              udap_client_registration_status: {
                name: :udap_client_credentials_flow_client_registration_status
              },
              udap_client_keyset_source: {
                name: :udap_client_credentials_client_keyset_source,
                title: 'Client Credentials Client Cert & Private Key Source'
              },
              udap_client_cert_pem: {
                name: :udap_client_credentials_flow_client_cert_pem,
                title: 'Client Credentials Client Certificate(s) (PEM Format)'
              },
              udap_client_private_key_pem: {
                name: :udap_client_credentials_flow_client_private_key,
                title: 'Client Credentials Client Private Key (PEM Format)'
              },
              udap_cert_iss: {
                name: :udap_cert_iss_client_creds_flow,
                title: 'Client Credentials JWT Issuer (iss) Claim'
              },
              udap_registration_requested_scope: {
                name: :udap_client_credentials_flow_registration_scope,
                title: 'Client Credentials Registration Requested Scope(s)',
                description: %(
                  String containing a space delimited list of scopes requested by the client application for use in
                  subsequent requests. The Authorization Server MAY consider this list when deciding the scopes that it
                  will allow the application to subsequently request. Apps requesting the "client_credentials" grant
                  type SHOULD request system scopes.
                )
              },
              udap_registration_certifications: {
                name: :udap_client_creds_flow_registration_certifications,
                title: 'Client Credentials UDAP Registration Certifications'
              }
            },
            outputs: {
              udap_client_cert_pem: {
                name: :udap_client_credentials_flow_client_cert_pem
              },
              udap_client_private_key_pem: {
                name: :udap_client_credentials_flow_client_private_key
              },
              udap_cert_iss: {
                name: :udap_cert_iss_client_creds_flow
              }
            }
          } do
      input_order :udap_registration_endpoint,
                  :udap_client_credentials_flow_registration_grant_type,
                  :udap_client_credentials_flow_client_registration_status,
                  :udap_cert_iss_client_creds_flow,
                  :udap_client_credentials_client_keyset_source,
                  :udap_client_credentials_flow_client_cert_pem,
                  :udap_client_credentials_flow_client_private_key,
                  :udap_client_credentials_flow_registration_scope,
                  :udap_jwt_signing_alg, :udap_client_creds_flow_registration_certifications
    end

    group from: :udap_client_credentials_authentication_group,
          run_as_group: true
  end
end
