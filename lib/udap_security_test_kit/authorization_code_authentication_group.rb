require_relative 'authorization_code_redirect_test'
require_relative 'authorization_code_received_test'
require_relative 'authorization_code_token_exchange_test'
require_relative 'token_exchange_response_body_test'
require_relative 'token_exchange_response_headers_test'
module UDAPSecurityTestKit
  class AuthorizationCodeAuthenticationGroup < Inferno::TestGroup
    title 'UDAP Authorization Code Authorization & Authentication'
    description %(
      This group tests the use of the authorization_code grant type to receive an authorization code from the
      authorization server and exchange it for an access token, as described
      in the [consumer-facing](https://hl7.org/fhir/us/udap-security/STU1/consumer.html) and
      [business-to-business (B2B)](https://hl7.org/fhir/us/udap-security/STU1/b2b.html) profiles requirements.
    )
    id :udap_authorization_code_authentication_group

    config inputs: {
      udap_client_id: {
        name: :udap_authorization_code_flow_client_id
      }
    }

    test from: :udap_authorization_code_redirect
    test from: :udap_authorization_code_received
    test from: :udap_authorization_code_token_exchange,
         config: {
           requests: {
             token_exchange: {
               name: :udap_auth_code_flow_token_exchange
             }
           }
         }
    test from: :udap_token_exchange_response_body,
         config: {
           inputs: {
             token_response_body: {
               name: :udap_auth_code_flow_token_exchange_response_body
             }
           },
           outputs: {
             udap_access_token: {
               name: :udap_auth_code_flow_access_token
             },
             udap_expires_in: {
               name: :udap_auth_code_flow_expires_in
             },
             udap_received_scopes: {
               name: :udap_auth_code_flow_received_scopes
             },
             udap_refresh_token: {
               name: :udap_auth_code_flow_refresh_token
             }
           }
         }
    test from: :udap_token_exchange_response_headers,
         config: {
           requests: {
             token_exchange: {
               name: :udap_auth_code_flow_token_exchange
             }
           }
         }
  end
end
