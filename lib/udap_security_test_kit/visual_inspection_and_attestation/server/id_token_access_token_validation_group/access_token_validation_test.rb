module UDAPSecurityTestKit
  class AccessTokenValidationAttestationTest < Inferno::Test
    title 'Access Token is validated correctly'
    id :udap_security_access_token_validation
    description %(
      The Data Holder SHALL validate the Access Token as per the Access Token validation rules.
      This includes verifying the token's integrity, claims, and expiration.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@283',
                          'hl7.fhir.us.udap-security@290'

    input :access_token_validation_correct,
          title: "Access Token is validated correctly",
          description: %(
            I attest that the Data Holder validates the Access Token as per the Access Token validation rules, including:
            - Verifying the token's integrity.
            - Checking claims such as `exp` and other relevant attributes.
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
    input :access_token_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert access_token_validation_correct == 'true',
              'Access Token validation is not implemented correctly as per the Access Token validation rules.'
      pass access_token_validation_note if access_token_validation_note.present?
    end
  end
end
