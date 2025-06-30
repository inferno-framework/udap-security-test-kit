module UDAPSecurityTestKit
  class ValidStateErrorResponseAttestationTest < Inferno::Test
    title 'Valid state error response is handled correctly'
    id :udap_security_valid_state_error_response
    description %(
      If the `state` value is valid on an error response, the Resource Holder MUST redirect with an `access_denied` error code.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@273'

    input :valid_state_error_response_handling_correct,
          title: "Valid state error response is handled correctly",
          description: %(
            I attest that the Resource Holder redirects with an `access_denied` error code when the `state` value is valid on an error response.
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
              'Resource Holder does not redirect with an `access_denied` error code when the `state` value is valid on an error response.'
      pass valid_state_error_response_handling_note if valid_state_error_response_handling_note.present?
    end
  end
end
