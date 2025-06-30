module UDAPSecurityTestKit
  class ClientSecurityAndCSRFProtectionAttestationTest < Inferno::Test
    title 'Client Security and CSRF Protection Compliance'
    id :udap_security_client_security_csrf_protection
    description %(
      Client applications SHALL comply with the requirements for Client Security and CSRF Protection:
      - Implement CSRF protection for its redirection URI.
      - Use a binding value for CSRF protection that contains a non-guessable value.
      - Ensure the user-agent's authenticated state is accessible only to the client and user-agent, protected by the same-origin policy.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@275',
                          'hl7.fhir.us.udap-security@276',
                          'hl7.fhir.us.udap-security@277'

    input :csrf_protection_implementation,
          title: "Client application implements CSRF protection for its redirection URI",
          description: %(
            I attest that the client application implements CSRF protection for its redirection URI to prevent cross-site request forgery attacks.
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
    input :csrf_protection_implementation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    input :csrf_binding_value_compliance,
          title: "Client application uses a non-guessable binding value for CSRF protection",
          description: %(
            I attest that the client application uses a binding value for CSRF protection that contains a non-guessable value to ensure security.
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
    input :csrf_binding_value_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    input :authenticated_state_protection,
          title: "Client application ensures authenticated state is protected by same-origin policy",
          description: %(
            I attest that the client application ensures the user-agent's authenticated state is stored in a location accessible only to the client and user-agent, protected by the same-origin policy.
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
    input :authenticated_state_protection_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert csrf_protection_implementation == 'true',
             'Client application did not implement CSRF protection for its redirection URI.'
      pass csrf_protection_implementation_note if csrf_protection_implementation_note.present?

      assert csrf_binding_value_compliance == 'true',
             'Client application did not use a non-guessable binding value for CSRF protection.'
      pass csrf_binding_value_compliance_note if csrf_binding_value_compliance_note.present?

      assert authenticated_state_protection == 'true',
             'Client application did not ensure the user-agent\'s authenticated state is protected by the same-origin policy.'
      pass authenticated_state_protection_note if authenticated_state_protection_note.present?
    end
  end
end
