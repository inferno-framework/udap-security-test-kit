module UDAPSecurityTestKit
  class PreferredIdentityProviderAttestationTest < Inferno::Test
    title 'Client indicates preferred Identity Provider'
    id :udap_security_preferred_idp
    description %(
      Client applications SHALL indicate the preferred Identity Provider (IdP) to the data holder by:
      - Adding `udap` to the list of scopes provided in the `scope` query parameter.
      - Adding the extension query parameter `idp` with a value equal to the base URL of the preferred OIDC IdP.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@236',
                          'hl7.fhir.us.udap-security@237'

    input :indicates_preferred_idp,
          title: "Client indicates preferred Identity Provider",
          description: %(
            I attest that the client application indicates the preferred Identity Provider (IdP) to the data holder by:
            - Adding `udap` to the list of scopes provided in the `scope` query parameter.
            - Adding the extension query parameter `idp` with a value equal to the base URL of the preferred OIDC IdP.
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
    input :indicates_preferred_idp_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert indicates_preferred_idp == 'true',
              'Client application did not demonstrate correct indication of the preferred Identity Provider.'
      pass indicates_preferred_idp_note if indicates_preferred_idp_note.present?
    end
  end
end
