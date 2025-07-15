module UDAPSecurityTestKit
  class TokenResponseValidationAttestationTest < Inferno::Test
    title 'Validates token response correctly'
    id :udap_security_token_response_validation
    description %(
      Client validates the Token Response as per RFC 6749 and OIDC Core specifications, including:
      - Ensuring the presence of `access_token` and `token_type` parameters.
      - Validating the response structure and data integrity.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@283',
                          'hl7.fhir.us.udap-security_1.0.0@284',
                          'hl7.fhir.us.udap-security_1.0.0@285'

    input :token_response_validation_correct,
          title: 'ID Token and Access Token Validation: Validates token response correctly',
          description: %(
            I attest that the Client validates the Token Response as per RFC 6749 and OIDC Core specifications,
            including:
            - Ensuring the presence of `access_token` and `token_type` parameters.
            - Validating the response structure and data integrity.
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
    input :token_response_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert token_response_validation_correct == 'true',
             'Token Response validation is not implemented correctly as per RFC 6749 and OIDC Core specifications.'
      pass token_response_validation_note if token_response_validation_note.present?
    end
  end
end
