module UDAPSecurityTestKit
  class JwtGrantParameterValidationAttestationTest < Inferno::Test
    title 'Authorization Server validates parameters per grant mechanism'
    id :udap_security_jwt_grant_parameter_validation
    description %(
      The Authorization Server validates all other parameters in the token request as per the
      requirements of the grant mechanism identified by the grant_type value.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@182'

    input :jwt_grant_parameter_validation_correct,
          title: 'JWT/Token Validation and Security: Parameter validation per grant mechanism',
          description: %(
            I attest that the Authorization Server validates all other parameters in the token request
            as per the requirements of the grant mechanism identified by the grant_type value.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :jwt_grant_parameter_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert jwt_grant_parameter_validation_correct == 'true',
             'The Authorization Server does not validate parameters as required by the grant mechanism.'
      pass jwt_grant_parameter_validation_note if jwt_grant_parameter_validation_note.present?
    end
  end
end
