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

    test from: :udap_client_credentials_token_exchange,
         config: {
           requests: {
             token_exchange: {
               name: :client_credentials_token_exchange
             }
           }
         }
    test from: :udap_token_exchange_response_body,
         config: {
           inputs: {
             token_response_body: {
               name: :client_credentials_token_response_body
             }
           }
         }
    test from: :udap_token_exchange_response_headers,
         config: {
           requests: {
             token_exchange: {
               name: :client_credentials_token_exchange
             }
           }
         }
  end
end
