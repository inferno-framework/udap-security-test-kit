module UDAPSecurityTestKit
  class AuthorizationCodeUsageAttestationTest < Inferno::Test
    title 'Authorization code is used correctly'
    id :udap_security_client_auth_code_usage
    description %(
      Client applications SHALL use the authorization code correctly by:
      - Ensuring the authorization code is not used more than once.
      - Requesting an authorization code as per Section 4.1.1 of RFC 6749.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@136',
                          'hl7.fhir.us.udap-security@188'

    input :authorization_code_usage_correctly,
          title: "Authorization code is used correctly",
          description: %(
            I attest that the client application uses the authorization code correctly by:
            - Ensuring the authorization code is not used more than once.
            - Requesting an authorization code as per Section 4.1.1 of RFC 6749.
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
    input :authorization_code_usage_correctly_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert authorization_code_usage_correctly == 'true',
              'Client application did not demonstrate correct usage of the authorization code.'
      pass authorization_code_usage_correctly_note if authorization_code_usage_correctly_note.present?
    end
  end
end
