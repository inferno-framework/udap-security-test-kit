module UDAPSecurityTestKit
  class JwtSignatureValidationAttestationTest < Inferno::Test
    title 'Validates JWT signature using public key from x5c parameter'
    id :udap_security_jwt_signature_validation
    description %(
      The Authorization Server validates the digital signature on the Authentication Token using the public key
      extracted from the first certificate in the x5c parameter of the JOSE header.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@173'

    input :jwt_signature_validation_correct,
          title: 'JWT/Token Validation and Security: Validates JWT signature using public key from x5c parameter',
          description: %(
            I attest that the Authorization Server validates the digital signature on the Authentication Token
            using the public key extracted from the first certificate in the x5c parameter of the JOSE header.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :jwt_signature_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert jwt_signature_validation_correct == 'true',
             'The Authorization Server does not validate the JWT signature using the x5c public key.'
      pass jwt_signature_validation_note if jwt_signature_validation_note.present?
    end
  end
end
