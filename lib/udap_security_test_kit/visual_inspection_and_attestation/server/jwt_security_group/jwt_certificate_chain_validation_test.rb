module UDAPSecurityTestKit
  class JwtCertificateChainValidationAttestationTest < Inferno::Test
    title 'Builds and validates trusted certificate chain for x5c'
    id :udap_security_jwt_certificate_chain_validation
    description %(
      The Authorization Server builds and validates a trusted certificate chain for the certificates in
      the x5c parameter of the JOSE header on Authentication Tokens in token requests.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@176'

    input :jwt_certificate_chain_validation_correct,
          title: 'JWT/Token Validation and Security: Builds and validates trusted certificate chain for x5c',
          description: %(
            I attest that the Authorization Server builds and validates a trusted certificate chain for the
            certificates in the x5c parameter of the JOSE header on Authentication Tokens in token requests.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :jwt_certificate_chain_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert jwt_certificate_chain_validation_correct == 'true',
             'The Authorization Server does not build and validate a trusted certificate chain for x5c certificates.'
      pass jwt_certificate_chain_validation_note if jwt_certificate_chain_validation_note.present?
    end
  end
end
