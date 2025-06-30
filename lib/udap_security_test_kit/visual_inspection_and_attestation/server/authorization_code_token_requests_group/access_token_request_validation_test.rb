module UDAPSecurityTestKit
  class AccessTokenRequestValidationAttestationTest < Inferno::Test
    title 'Access token request is validated correctly'
    id :udap_security_access_token_request_validation
    description %(
      The Authorization Server SHALL validate access token requests by:
      - Requiring client authentication for confidential clients or clients issued credentials.
      - Authenticating the client if client authentication is included.
      - Verifying that the authorization code is valid.
      - Ensuring the `redirect_uri` parameter is present and matches the initial authorization request.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@146',
                          'hl7.fhir.us.udap-security@147',
                          'hl7.fhir.us.udap-security@149',
                          'hl7.fhir.us.udap-security@150'

    input :access_token_request_validation_correct,
          title: "Access token request is validated correctly",
          description: %(
            I attest that the Authorization Server validates access token requests by:
            - Requiring client authentication for confidential clients or clients issued credentials.
            - Authenticating the client if client authentication is included.
            - Verifying that the authorization code is valid.
            - Ensuring the `redirect_uri` parameter is present and matches the initial authorization request.
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
    input :access_token_request_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert access_token_request_validation_correct == 'true',
              'Authorization Server did not validate access token requests correctly.'
      pass access_token_request_validation_note if access_token_request_validation_note.present?
    end
  end
end
