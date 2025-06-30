module UDAPSecurityTestKit
  class StateMismatchErrorAttestationTest < Inferno::Test
    title 'State mismatch error is handled correctly'
    id :udap_security_state_mismatch_error
    description %(
      If the `state` parameter does NOT match, the Resource Holder MUST terminate the workflow and redirect with a `server_error`.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@271'

    input :state_mismatch_error_handling_correct,
          title: "State mismatch error is handled correctly",
          description: %(
            I attest that the Resource Holder terminates the workflow and redirects with a `server_error` when the `state` parameter does NOT match.
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
    input :state_mismatch_error_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert state_mismatch_error_handling_correct == 'true',
              'Resource Holder does not terminate the workflow or redirect with a `server_error` when the `state` parameter does NOT match.'
      pass state_mismatch_error_handling_note if state_mismatch_error_handling_note.present?
    end
  end
end
