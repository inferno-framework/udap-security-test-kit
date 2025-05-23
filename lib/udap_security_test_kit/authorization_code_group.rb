require_relative 'dynamic_client_registration_group'
require_relative 'discovery_group'
require_relative 'authorization_code_authentication_group'
module UDAPSecurityTestKit
  class AuthorizationCodeGroup < Inferno::TestGroup
    title 'UDAP Authorization Code Flow'
    description %(
      This group tests UDAP servers that support JWT authentication using an OAuth2.0 authorization_code grant flow and
       includes the following sub-groups.

      1. Discovery Group
      2. Dynamic Client Registration
      3. Authorization and Authentication - supports both [Consumer Facing](https://hl7.org/fhir/us/udap-security/STU1/consumer.html)
      and [Business-to-Business (B2B)](https://hl7.org/fhir/us/udap-security/STU1/b2b.html) profiles in the UDAP IG
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
                name: :udap_auth_code_flow_registration_grant_type,
                default: 'authorization_code',
                locked: true
              },
              udap_client_registration_status: {
                name: :udap_auth_code_flow_client_registration_status
              },
              udap_client_cert_pem: {
                name: :udap_auth_code_flow_client_cert_pem,
                title: 'Authorization Code Client Certificate(s) (PEM Format)'
              },
              udap_client_private_key_pem: {
                name: :udap_auth_code_flow_client_private_key,
                title: 'Authorization Code Client Private Key (PEM Format)'
              },
              udap_cert_iss: {
                name: :udap_auth_code_flow_cert_iss,
                title: 'Authorization Code JWT Issuer (iss) Claim'
              },
              udap_registration_requested_scope: {
                name: :udap_auth_code_flow_registration_scope,
                title: 'Authorization Code Registration Requested Scope(s)',
                description: %(
                  String containing a space delimited list of scopes requested by the client application for use in
                  subsequent requests. The Authorization Server MAY consider this list when deciding the scopes that it
                  will allow the application to subsequently request. Apps requesting the "authorization_code" grant
                  type SHOULD request user or patient scopes.
                )
              },
              udap_registration_certifications: {
                name: :udap_auth_code_flow_registration_certifications,
                title: 'Authorization Code UDAP Registration Certifications'
              }
            },
            outputs: {
              udap_client_id: {
                name: :udap_authorization_code_flow_client_id
              }
            }
          } do
      input_order :udap_registration_endpoint,
                  :udap_auth_code_flow_registration_grant_type,
                  :udap_auth_code_flow_client_registration_status,
                  :udap_auth_code_flow_client_cert_pem,
                  :udap_auth_code_flow_client_private_key,
                  :udap_auth_code_flow_cert_iss,
                  :udap_auth_code_flow_registration_scope,
                  :udap_jwt_signing_alg, :udap_auth_code_flow_registration_certifications
    end

    group from: :udap_authorization_code_authentication_group,
          run_as_group: true
  end
end
