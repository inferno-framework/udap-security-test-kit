module UDAPSecurityTestKit
  class UnauthenticatedUserErrorAttestationTest < Inferno::Test
    title 'Unauthenticated user error is handled correctly'
    id :udap_security_unauthenticated_user_error
    description %(
      If the Data Holder cannot resolve the authenticated user, it SHALL return an `access_denied` error response.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@296'

    input :unauthenticated_user_error_handling_correct,
          title: "Unauthenticated user error is handled correctly",
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
