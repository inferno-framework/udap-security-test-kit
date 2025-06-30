module UDAPSecurityTestKit
  class PrivateKeyAuthenticationAttestationTest < Inferno::Test
    title 'Client uses private key authentication correctly'
    id :udap_security_private_key_authentication
    description %(
      Client applications SHALL use private key authentication correctly by:
      - Omitting the HTTP Authorization header and client secret in token endpoint requests when authenticating with a private key and Authentication Token.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@164',
                          'hl7.fhir.us.udap-security@224'

    input :private_key_authentication_correctly,
          title: "Client uses private key authentication correctly",
          description: %(
            I attest that the client application uses private key authentication correctly by:
            - Omitting the HTTP Authorization header and client secret in token endpoint requests when authenticating with a private key and Authentication Token.
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
    input :private_key_authentication_correctly_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert private_key_authentication_correctly == 'true',
              'Client application did not demonstrate correct private key authentication.'
      pass private_key_authentication_correctly_note if private_key_authentication_correctly_note.present?
    end
  end
end