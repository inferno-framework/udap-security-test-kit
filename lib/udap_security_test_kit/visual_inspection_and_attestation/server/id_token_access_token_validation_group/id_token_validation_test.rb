module UDAPSecurityTestKit
  class IDTokenValidationAttestationTest < Inferno::Test
    title 'ID Token is validated correctly'
    id :udap_security_id_token_validation
    description %(
      The Data Holder SHALL validate the ID Token as per OIDC Core specifications.
      This includes verifying the token's signature, claims, issuer, audience, and expiration.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@282',
                          'hl7.fhir.us.udap-security@289'

    input :id_token_validation_correct,
          title: "ID Token is validated correctly",
          description: %(
            I attest that the Data Holder validates the ID Token as per OIDC Core specifications, including:
            - Verifying the token's signature.
            - Checking claims such as `iss`, `aud`, and `exp`.
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
    input :id_token_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert id_token_validation_correct == 'true',
              'ID Token validation is not implemented correctly as per OIDC Core specifications.'
      pass id_token_validation_note if id_token_validation_note.present?
    end
  end
end
