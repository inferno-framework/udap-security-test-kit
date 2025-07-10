module UDAPSecurityTestKit
  class AuthorizationCodeUsageAttestationTest < Inferno::Test
    title 'Ensures authorization code is used correctly'
    id :udap_security_auth_code_usage
    description %(
      The Authorization Server ensures that:
      - Authorization codes are not used more than once.
      - Authorization codes expire shortly after issuance to mitigate the risk of leaks.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@135',
                          'hl7.fhir.us.udap-security_1.0.0@137'

    input :authorization_code_usage_correct,
          title: "Authorization Code and Token Requests: Ensures Authorization Code is used correctly",
          description: %(
            I attest that the Authorization Server ensures:
            - Authorization codes are not used more than once.
            - Authorization codes expire shortly after issuance to mitigate the risk of leaks.
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
    input :authorization_code_usage_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert authorization_code_usage_correct == 'true',
              'Authorization Server did not ensure correct usage of authorization codes.'
      pass authorization_code_usage_note if authorization_code_usage_note.present?
    end
  end
end
