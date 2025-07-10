module UDAPSecurityTestKit
  class ValidStateErrorResponseAttestationTest < Inferno::Test
    title 'Handles valid state error correctly'
    id :udap_security_valid_state_error_response
    description %(
      Resource Holder redirects with an `access_denied` error code when the `state` value is valid
      on an error response.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@273'

    input :valid_state_error_response_handling_correct,
          title: 'Error Handling: Handles valid state error correctly',
          description: %(
            I attest that the Resource Holder redirects with an `access_denied` error code when the
            `state` value is valid on an error response.
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
    input :valid_state_error_response_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert valid_state_error_response_handling_correct == 'true',
             'Resource Holder does not redirect with an `access_denied` error code when the `state`
              value is valid on an error response.'
      pass valid_state_error_response_handling_note if valid_state_error_response_handling_note.present?
    end
  end
end
