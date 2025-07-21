module UDAPSecurityTestKit
  class JwtTokenRequestValidationAttestationTest < Inferno::Test
    title 'Validates and responds to token requests per UDAP JWT-Based Client Authentication'
    id :udap_security_jwt_token_request_validation
    description %(
      The Authorization Server validates and responds to token requests containing Authentication Tokens
      as per [Sections 6 and 7 of UDAP JWT-Based Client Authentication](https://www.udap.org/udap-jwt-client-auth.html).
    )
    verifies_requirements(
      'hl7.fhir.us.udap-security_1.0.0@172',
      'hl7.fhir.us.udap-security_1.0.0@229'
    )

    input :jwt_token_request_validation_correct,
          title: %(
            JWT/Token Validation and Security: Validates and responds to token requests per UDAP JWT-Based
            Client Authentication
          ),
          description: %(
            I attest that the Authorization Server validates and responds to token requests containing
            Authentication Tokens as per [Sections 6 and 7 of UDAP JWT-Based Client Authentication](https://www.udap.org/udap-jwt-client-auth.html).
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :jwt_token_request_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert jwt_token_request_validation_correct == 'true',
             'The Authorization Server does not validate and respond to token requests as per UDAP JWT-Based
              Client Authentication.'
      pass jwt_token_request_validation_note if jwt_token_request_validation_note.present?
    end
  end
end
