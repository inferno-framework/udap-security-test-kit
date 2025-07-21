module UDAPSecurityTestKit
  class ClientSecurityAndCSRFProtectionAttestationTest < Inferno::Test
    title 'Complies with Client Security and CSRF Protection'
    id :udap_security_client_security_csrf_protection
    description %(
      Client applications complies with the requirements for Client Security and CSRF Protection:
      - Implements CSRF protection for its redirection URI.
      - Uses a binding value for CSRF protection that contains a non-guessable value.
      - Ensures the user-agent's authenticated state is accessible only to the client and user-agent, protected by
        the same-origin policy.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@275',
                          'hl7.fhir.us.udap-security_1.0.0@276',
                          'hl7.fhir.us.udap-security_1.0.0@277'

    input :csrf_protection_implementation,
          title: 'Complies with the requirements for Client Security and CSRF Protection',
          description: %(
            I attest that the client application complies with the requirements for Client Security and CSRF Protection:
            - Implements CSRF protection for its redirection URI.
            - Uses a binding value for CSRF protection that contains a non-guessable value.
            - Ensures the user-agent's authenticated state is accessible only to the client and user-agent, protected by
              the same-origin policy.
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

    run do
      assert csrf_protection_implementation == 'true',
             'Client application did not comply with the requirements for Client Security and CSRF Protection.'
      pass csrf_protection_implementation_note if csrf_protection_implementation_note.present?
    end
  end
end
