module UDAPSecurityTestKit
  class AuthenticationRequestValidationAttestationTest < Inferno::Test
    title 'Authentication Request Validation Compliance'
    id :oidc_auth_request_validation
    description %(
      The Authorization Server SHALL validate authentication requests according to OpenID Connect requirements, including:
      - Validation of all OAuth 2.0 parameters.
      - Verification that the `scope` parameter contains the `openid` value.
      - Verification of the presence and conformity of required parameters.
      - Proper handling of the `sub` Claim, `id_token_hint`, and `prompt` parameter.
      - Implementation of CSRF and Clickjacking protections.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@258',
                          'hl7.fhir.us.udap-security@259',
                          'hl7.fhir.us.udap-security@260',
                          'hl7.fhir.us.udap-security@261',
                          'hl7.fhir.us.udap-security@262',
                          'hl7.fhir.us.udap-security@263',
                          'hl7.fhir.us.udap-security@264',
                          'hl7.fhir.us.udap-security@265',
                          'hl7.fhir.us.udap-security@266',
                          'hl7.fhir.us.udap-security@267',
                          'hl7.fhir.us.udap-security@269'

    input :auth_request_validation_correct,
          title: "Authentication Request Validation Compliance",
          description: %(
            I attest that the Authorization Server ensures:
            - Validation of all OAuth 2.0 parameters.
            - Verification that the `scope` parameter contains the `openid` value.
            - Required parameters are present and conform to the specification.
            - Proper handling of the `sub` Claim, `id_token_hint`, and `prompt` parameter.
            - Implementation of CSRF and Clickjacking protections.
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
    input :auth_request_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert auth_request_validation_correct == 'true',
              'Authentication Request Validation does not comply with OpenID Connect requirements.'
      pass auth_request_validation_note if auth_request_validation_note.present?
    end
  end
end
