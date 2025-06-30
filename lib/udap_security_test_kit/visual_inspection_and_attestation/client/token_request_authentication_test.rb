module UDAPSecurityTestKit
  class TokenRequestAuthenticationAttestationTest < Inferno::Test
    title 'Client authenticates correctly when making token requests'
    id :udap_security_token_request_authentication
    description %(
      Client applications SHALL authenticate correctly when making token requests by:
      - Including the `client_id` parameter in the token request if the client is not authenticating with the authorization server.
      - Authenticating to the Token Endpoint using the method registered for its `client_id` if the client is a Confidential Client.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@144',
                          'openid.connect.core@280'

    input :token_request_authentication_correctly,
          title: "Client authenticates correctly when making token requests",
          description: %(
            I attest that the client application authenticates correctly when making token requests by:
            - Including the `client_id` parameter in the token request if the client is not authenticating with the authorization server.
            - Authenticating to the Token Endpoint using the method registered for its `client_id` if the client is a Confidential Client.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              {
                label: 'Yes',
                value: 'true'
              },
              {
                label: 'No',
                value: 'false'
              }
            ]
          }
    input :token_request_authentication_correctly_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert token_request_authentication_correctly == 'true',
              'Client application did not demonstrate correct authentication during token requests.'
      pass token_request_authentication_correctly_note if token_request_authentication_correctly_note.present?
    end
  end
end
