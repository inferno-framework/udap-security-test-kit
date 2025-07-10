module UDAPSecurityTestKit
  class AuthenticationRequestValidationAttestationTest < Inferno::Test
    title 'OpenID Connect Authentication Requests: Complies with OpenID Connect requirements in validation'
    id :oidc_auth_request_validation
    description %(
      Authorization Server complies with OpenID Connect requirements and ensures:
            - Validation of all OAuth 2.0 parameters.
            - Verification that the `scope` parameter contains the `openid` value.
            - Required parameters are present and conform to the specification.
            - Proper handling of the `sub` Claim, `id_token_hint`, and `prompt` parameter.
            - Implementation of CSRF and Clickjacking protections.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@258',
                          'hl7.fhir.us.udap-security_1.0.0@259',
                          'hl7.fhir.us.udap-security_1.0.0@260',
                          'hl7.fhir.us.udap-security_1.0.0@261',
                          'hl7.fhir.us.udap-security_1.0.0@262',
                          'hl7.fhir.us.udap-security_1.0.0@263',
                          'hl7.fhir.us.udap-security_1.0.0@264',
                          'hl7.fhir.us.udap-security_1.0.0@265',
                          'hl7.fhir.us.udap-security_1.0.0@266',
                          'hl7.fhir.us.udap-security_1.0.0@267',
                          'hl7.fhir.us.udap-security_1.0.0@269'

    input :auth_request_validation_correct,
          title: 'OpenID Connect Authentication Requests: Complies with OpenID Connect requirements in validation',
          description: %(
            I attest that the Authorization Server complies with OpenID Connect requirements and ensures:
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
