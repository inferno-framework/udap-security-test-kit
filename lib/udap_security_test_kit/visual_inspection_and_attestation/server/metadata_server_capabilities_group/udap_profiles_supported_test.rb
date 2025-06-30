module UDAPSecurityTestKit
  class UDAPProfilesSupportedAttestationTest < Inferno::Test
    title 'UDAP Metadata includes supported profiles'
    id :udap_security_profiles_supported
    description %(
      If the server supports the user authentication workflow described in Section 6, the `udap_profiles_supported` element SHALL include `udap_to` for UDAP Tiered OAuth for User Authentication.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@27'

    input :udap_profiles_supported_correct,
          title: "UDAP Metadata includes supported profiles",
          description: %(
            I attest that the server's UDAP metadata includes the `udap_profiles_supported` element with `udap_to` if the server supports the user authentication workflow described in Section 6.
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
    input :udap_profiles_supported_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert udap_profiles_supported_correct == 'true',
              'Server metadata does not include the `udap_profiles_supported` element with `udap_to` for UDAP Tiered OAuth for User Authentication.'
      pass udap_profiles_supported_note if udap_profiles_supported_note.present?
    end
  end
end
