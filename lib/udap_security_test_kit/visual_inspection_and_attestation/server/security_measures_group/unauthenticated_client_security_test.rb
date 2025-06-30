module UDAPSecurityTestKit
  class UnauthenticatedClientSecurityAttestationTest < Inferno::Test
    title 'Security measures are considered for unauthenticated clients'
    id :udap_security_unauthenticated_clients
    description %(
      The Authorization Server MUST consider security implications of interacting with unauthenticated clients to prevent unauthorized access or misuse.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@288'

    input :unauthenticated_client_security_measures,
          title: "Security measures are considered for unauthenticated clients",
          description: %(
            I attest that the Authorization Server considers security implications when interacting with unauthenticated clients, including:
            - Restricting access to sensitive endpoints.
            - Implementing rate limiting or other protective measures.
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
    input :unauthenticated_client_security_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert unauthenticated_client_security_measures == 'true',
              'Authorization Server does not consider security implications when interacting with unauthenticated clients.'
      pass unauthenticated_client_security_note if unauthenticated_client_security_note.present?
    end
  end
end
