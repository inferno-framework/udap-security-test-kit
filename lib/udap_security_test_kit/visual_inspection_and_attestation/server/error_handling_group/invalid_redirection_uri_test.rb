module UDAPSecurityTestKit
  class InvalidRedirectionURIAttestationTest < Inferno::Test
    title 'Handles invalid redirection URI correctly'
    id :udap_security_invalid_redirection_uri
    description %(
      The Authorization Server does NOT redirect the user-agent to an invalid redirection URI when the request fails due to a missing or invalid redirection URI.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@242'

    input :invalid_redirection_uri_handling_correct,
          title: 'Error Handling: Handles Invalid redirection URI correctly',
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
