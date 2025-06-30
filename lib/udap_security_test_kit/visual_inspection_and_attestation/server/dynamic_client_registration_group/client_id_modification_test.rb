module UDAPSecurityTestKit
  class ClientIDModificationAttestationTest < Inferno::Test
    title 'Authorization Server handles client ID modification correctly'
    id :udap_security_client_id_modification
    description %(
      If the Authorization Server returns a different `client_id` in response to a registration modification request, it SHALL cancel the registration for the previous `client_id`.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@121'

    input :client_id_modification_correct,
          title: "Authorization Server handles client ID modification correctly",
          description: %(
            I attest that the Authorization Server cancels the registration for the previous `client_id` if it returns a different `client_id` in response to a registration modification request.
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
    input :client_id_modification_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert client_id_modification_correct == 'true',
              'Authorization Server did not handle client ID modification correctly.'
      pass client_id_modification_note if client_id_modification_note.present?
    end
  end
end
