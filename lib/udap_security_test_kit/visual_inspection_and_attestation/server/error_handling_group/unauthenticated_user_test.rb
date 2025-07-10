module UDAPSecurityTestKit
  class UnauthenticatedUserErrorAttestationTest < Inferno::Test
    title 'Handles unauthenticated user error correctly'
    id :udap_security_unauthenticated_user_error
    description %(
      Data Holder returns an `access_denied` error response when it cannot resolve the authenticated user.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@296'

    input :unauthenticated_user_error_handling_correct,
          title: 'Error Handling: Handles unauthenticated user error correctly',
          description: %(
            I attest that the Data Holder returns an `access_denied` error response when it cannot resolve the authenticated user.
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
    input :unauthenticated_user_error_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert unauthenticated_user_error_handling_correct == 'true',
             'Data Holder does not return an `access_denied` error response when it cannot resolve the authenticated user.'
      pass unauthenticated_user_error_handling_note if unauthenticated_user_error_handling_note.present?
    end
  end
end
