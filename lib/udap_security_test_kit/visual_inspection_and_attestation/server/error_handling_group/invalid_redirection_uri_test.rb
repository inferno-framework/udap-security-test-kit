module UDAPSecurityTestKit
  class InvalidRedirectionURIAttestationTest < Inferno::Test
    title 'Invalid redirection URI is handled correctly'
    id :udap_security_invalid_redirection_uri
    description %(
      The Authorization Server MUST NOT redirect the user-agent to an invalid redirection URI if the request fails due to a missing or invalid redirection URI.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@242'

    input :invalid_redirection_uri_handling_correct,
          title: "Invalid redirection URI is handled correctly",
          description: %(
            I attest that the Authorization Server does NOT redirect the user-agent to an invalid redirection URI when the request fails due to a missing or invalid redirection URI.
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
    input :invalid_redirection_uri_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert invalid_redirection_uri_handling_correct == 'true',
              'Authorization Server redirects the user-agent to an invalid redirection URI when the request fails due to a missing or invalid URI.'
      pass invalid_redirection_uri_handling_note if invalid_redirection_uri_handling_note.present?
    end
  end
end
