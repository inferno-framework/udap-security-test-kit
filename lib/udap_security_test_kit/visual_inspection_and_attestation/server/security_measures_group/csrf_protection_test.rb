module UDAPSecurityTestKit
  class CSRFProtectionAttestationTest < Inferno::Test
    title 'Implements CSRF and Clickjacking protection'
    id :udap_security_csrf_protection
    description %(
      Authorization Server implements CSRF and Clickjacking protection as
      described in [RFC6749](https://openid.net/specs/openid-connect-core-1_0.html#RFC6749),
      including:
      - Use of anti-CSRF tokens.
      - Validation of `state` parameter to prevent cross-site request forgery.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@278',
                          'hl7.fhir.us.udap-security_1.0.0@269'

    input :csrf_protection_implemented,
          title: 'Security Measures: Implements CSRF and Clickjacking protection',
          description: %(
            I attest that the Authorization Server implements CSRF and Clickjacking protection as
            described in [RFC6749](https://openid.net/specs/openid-connect-core-1_0.html#RFC6749),
            including:
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
             'Authorization Server does not implement CSRF protection as described in RFC6749.'
      pass csrf_protection_note if csrf_protection_note.present?
    end
  end
end
