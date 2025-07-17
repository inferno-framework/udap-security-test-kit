module UDAPSecurityTestKit
  class StateParameterAttestationTest < Inferno::Test
    title 'Manages state parameter securely'
    id :udap_security_state_parameter_management
    description %(
      The Resource Holder:
      - Generates its own random value for the state parameter (does not reuse the value provided by the Client App).
      - Validates that the value of the state parameter in the query string matches the value it generated when the
        user is redirected back from the IdP.
      - Validates the value of the state parameter when receiving an error response from the IdP.
    )
    verifies_requirements(
      'hl7.fhir.us.udap-security_1.0.0@254',
      'hl7.fhir.us.udap-security_1.0.0@255',
      'hl7.fhir.us.udap-security_1.0.0@270',
      'hl7.fhir.us.udap-security_1.0.0@272'
    )

    input :state_parameter_management_correct,
          title: 'Security Measures: Manages state parameter securely',
          description: %(
            I attest that the Resource Holder:
            - Generates its own random value for the state parameter and does not reuse the value provided by the
              Client App.
            - Validates that the value of the state parameter in the query string matches the value it generated
              when the user is redirected back from the IdP.
            - Validates the value of the state parameter when receiving an error response from the IdP.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :state_parameter_management_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert state_parameter_management_correct == 'true',
             'Resource Holder does not properly generate or validate the state parameter as required.'
      pass state_parameter_management_note if state_parameter_management_note.present?
    end
  end
end
