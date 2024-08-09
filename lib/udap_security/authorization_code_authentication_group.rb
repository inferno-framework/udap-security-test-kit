require_relative 'authorization_code_redirect_test'
require_relative 'authorization_code_received_test'
require_relative 'authorization_code_token_exchange_test'
require_relative 'token_exchange_response_body_test'
require_relative 'token_exchange_response_headers_test'
module UDAPSecurity
  class AuthorizationCodeAuthenticationGroup < Inferno::TestGroup
    title 'UDAP Authorization Code Authorization & Authentication'
    description %(
      This group tests the use of the authorization_code grant type to receive an authorization code from the
      authorization server and exchange it for an access token, as described
      in the [consumer-facing](https://hl7.org/fhir/us/udap-security/STU1/consumer.html) and
      [business-to-business (B2B)](https://hl7.org/fhir/us/udap-security/STU1/b2b.html) profiles requirements.
    )
    id :udap_authorization_code_authentication_group

    test from: :udap_authorization_code_redirect
    test from: :udap_authorization_code_received
    test from: :udap_authorization_code_token_exchange,
         config: {
           requests: {
             token_exchange: {
               name: :authorization_code_token_exchange
             }
           }
         }
    test from: :udap_token_exchange_response_body,
         config: {
           inputs: {
             token_response_body: {
               name: :authorization_code_token_response_body
             }
           }
         }
    test from: :udap_token_exchange_response_headers,
         config: {
           requests: {
             token_exchange: {
               name: :authorization_code_token_exchange
             }
           }
         }
  end
end
