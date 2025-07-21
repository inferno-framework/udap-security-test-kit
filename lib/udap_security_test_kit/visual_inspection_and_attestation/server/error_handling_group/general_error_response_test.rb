module UDAPSecurityTestKit
  class GeneralErrorResponseAttestationTest < Inferno::Test
    title 'Returns error response on authentication request errors'
    id :udap_security_general_error_response
    description %(
      Authorization Server returns an error response if it encounters any error while validating
      an authentication request, as per
      [Section 3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation).
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@264'

    input :general_error_response_handling_correct,
          title: 'Error Handling: Returns error response on authentication request errors',
          description: %(
            I attest that the Authorization Server returns an error response if it encounters any
            error while validating an authentication request, as per
            [Section 3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation).
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :general_error_response_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert general_error_response_handling_correct == 'true',
             'Authorization Server does not return an error response when it encounters an error
              while validating an authentication request.'
      pass general_error_response_handling_note if general_error_response_handling_note.present?
    end
  end
end
