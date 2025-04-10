require_relative 'client_credentials_token_exchange_test'
require_relative 'token_exchange_response_body_test'
require_relative 'token_exchange_response_headers_test'

module UDAPSecurityTestKit
  class ClientCredentialsAuthenticationGroup < Inferno::TestGroup
    title 'UDAP Client Credentials Authorization & Authentication'
    description %(
      This group tests the use of the client_credentials grant type to authenticate to an authorization server and
      receive an access token, as described
      in the [business-to-business (B2B) profile requirements](https://hl7.org/fhir/us/udap-security/STU1/b2b.html).
    )
    id :udap_client_credentials_authentication_group

    config(
      requests: {
        token_exchange: {
          name: :udap_client_credentials_flow_token_exchange
        }
      },
      inputs: {
        udap_client_id: {
          name: :udap_client_credentials_flow_client_id
        },
        token_response_body: {
          name: :udap_client_credentials_flow_token_exchange_response_body
        }
      },
      outputs: {
        udap_access_token: {
          name: :udap_client_credentials_flow_access_token
        },
        udap_expires_in: {
          name: :udap_client_credentials_flow_expires_in
        },
        udap_received_scopes: {
          name: :udap_client_credentials_flow_received_scopes
        },
        udap_refresh_token: {
          name: :udap_client_credentials_flow_refresh_token
        }
      }
    )

    test from: :udap_client_credentials_token_exchange
    test from: :udap_token_exchange_response_body
    test from: :udap_token_exchange_response_headers
  end
end
