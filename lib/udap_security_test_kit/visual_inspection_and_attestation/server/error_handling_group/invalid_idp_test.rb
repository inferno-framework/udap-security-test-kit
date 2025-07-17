module UDAPSecurityTestKit
  class InvalidIdpErrorAttestationTest < Inferno::Test
    title 'Handles invalid_idp error correctly'
    id :udap_security_invalid_idp_error
    description %(
      Data Holder returns an error response with the `invalid_idp` extension error code
      when the IdP is rejected, as per
      [Section 4.1.2.1 of RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1).
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@241'

    input :invalid_idp_error_handling_correct,
          title: 'Error Handling: Handles invalid_idp error correctly',
          description: %(
            I attest that the Data Holder returns an error response with the `invalid_idp`
            extension error code when the IdP is rejected, as per
            [Section 4.1.2.1 of RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1).
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :invalid_idp_error_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert invalid_idp_error_handling_correct == 'true',
             'Data Holder does not return an error response with the `invalid_idp` extension error code when the
              IdP is rejected.'
      pass invalid_idp_error_handling_note if invalid_idp_error_handling_note.present?
    end
  end
end
