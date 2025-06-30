module UDAPSecurityTestKit
  class CSRFProtectionAttestationTest < Inferno::Test
    title 'CSRF protection is implemented for the authorization endpoint'
    id :udap_security_csrf_protection
    description %(
      The Authorization Server MUST implement CSRF protection for its authorization endpoint to prevent unauthorized or malicious requests.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@278'

    input :csrf_protection_implemented,
          title: "CSRF protection is implemented for the authorization endpoint",
          description: %(
            I attest that the Authorization Server implements CSRF protection for its authorization endpoint, including mechanisms such as:
            - Use of anti-CSRF tokens.
            - Validation of `state` parameter to prevent cross-site request forgery.
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
    input :csrf_protection_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert csrf_protection_implemented == 'true',
              'Authorization Server does not implement CSRF protection for its authorization endpoint.'
      pass csrf_protection_note if csrf_protection_note.present?
    end
  end
end
