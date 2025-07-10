module UDAPSecurityTestKit
  class InvalidIDTokenErrorAttestationTest < Inferno::Test
    title 'Handles invalid ID token error correctly'
    id :udap_security_invalid_id_token_error
    description %(
      Data Holder either returns an `invalid_idp` error code or attempts alternate authentication when the IdP
      does not return an ID Token or validation fails.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@291'

    input :invalid_id_token_error_handling_correct,
          title: 'Error Handling: Handles invalid ID token error correctly',
          description: %(
            I attest that the Data Holder either returns an `invalid_idp` error code or attempts alternate
            authentication when the IdP does not return an ID Token or validation fails.
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
    input :invalid_id_token_error_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert invalid_id_token_error_handling_correct == 'true',
             'Data Holder does not return an `invalid_idp` error code or attempt alternate authentication
              when the IdP does not return an ID Token or validation fails.'
      pass invalid_id_token_error_handling_note if invalid_id_token_error_handling_note.present?
    end
  end
end
