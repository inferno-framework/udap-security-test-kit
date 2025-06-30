module UDAPSecurityTestKit
  class UDAPAuthorizationExtensionsRequiredAttestationTest < Inferno::Test
    title 'UDAP Metadata includes required authorization extensions'
    id :udap_security_authorization_extensions_required
    description %(
      If the Authorization Server requires the B2B Authorization Extension Object, the `udap_authorization_extensions_required` list SHALL include `["hl7-b2b"]`.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@32'

    input :udap_authorization_extensions_required_correct,
          title: "UDAP Metadata includes required authorization extensions",
          description: %(
            I attest that the server's UDAP metadata includes the `udap_authorization_extensions_required` list with `["hl7-b2b"]` if the Authorization Server requires the B2B Authorization Extension Object.
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
    input :udap_authorization_extensions_required_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert udap_authorization_extensions_required_correct == 'true',
              'Server metadata does not include the `udap_authorization_extensions_required` list with `["hl7-b2b"]` when required.'
      pass udap_authorization_extensions_required_note if udap_authorization_extensions_required_note.present?
    end
  end
end
