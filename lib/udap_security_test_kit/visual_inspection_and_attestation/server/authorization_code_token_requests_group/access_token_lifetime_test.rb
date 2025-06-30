module UDAPSecurityTestKit
  class AccessTokenLifetimeAttestationTest < Inferno::Test
    title 'Access tokens have a lifetime of no longer than 60 minutes'
    id :udap_security_access_token_lifetime
    description %(
      The Authorization Server SHALL issue access tokens with a lifetime no longer than 60 minutes for all successful token requests.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@184'

    input :access_token_lifetime_correct,
          title: "Access tokens have a lifetime of no longer than 60 minutes",
          description: %(
            I attest that the Authorization Server issues access tokens with a lifetime no longer than 60 minutes for all successful token requests.
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
    input :access_token_lifetime_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert access_token_lifetime_correct == 'true',
              'Authorization Server did not issue access tokens with a lifetime no longer than 60 minutes.'
      pass access_token_lifetime_note if access_token_lifetime_note.present?
    end
  end
end
