module UDAPSecurityTestKit
  class ScopesAndIdentityProviderInteractionAttestationTest < Inferno::Test
    title 'Scopes and Identity Provider Interaction Compliance'
    id :udap_security_scopes_identity_provider_interaction
    description %(
      Client applications SHALL comply with the requirements for Scopes and Identity Provider Interaction:
      - The client app indicates the preferred Identity Provider by adding `udap` to the list of scopes in the `scope` query parameter.
      - The `scope` query parameter of the authentication request SHALL contain at least the values `openid` and `udap`.
      - The Identity Provider SHALL authenticate the user as per OIDC Core and UDAP Tiered OAuth specifications.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@236',
                          'hl7.fhir.us.udap-security@256',
                          'hl7.fhir.us.udap-security@257'

    input :scope_includes_udap,
          title: "Client application includes `udap` in the `scope` query parameter",
          description: %(
            I attest that the client application includes `udap` in the list of scopes provided in the `scope` query parameter to indicate the preferred Identity Provider.
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
    input :scope_includes_udap_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    input :scope_contains_openid_udap,
          title: "Client application ensures `scope` query parameter contains `openid` and `udap`",
          description: %(
            I attest that the client application ensures the `scope` query parameter of the authentication request contains at least the values `openid` and `udap`.
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
    input :scope_contains_openid_udap_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    input :idp_authentication_compliance,
          title: "Identity Provider authenticates user as per OIDC Core and UDAP Tiered OAuth specifications",
          description: %(
            I attest that the Identity Provider authenticates the user according to the OIDC Core and UDAP Tiered OAuth specifications.
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
    input :idp_authentication_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert scope_includes_udap == 'true',
             'Client application did not include `udap` in the `scope` query parameter to indicate the preferred Identity Provider.'
      pass scope_includes_udap_note if scope_includes_udap_note.present?

      assert scope_contains_openid_udap == 'true',
             'Client application did not ensure the `scope` query parameter contains at least `openid` and `udap`.'
      pass scope_contains_openid_udap_note if scope_contains_openid_udap_note.present?

      assert idp_authentication_compliance == 'true',
             'Identity Provider did not authenticate the user as per OIDC Core and UDAP Tiered OAuth specifications.'
      pass idp_authentication_compliance_note if idp_authentication_compliance_note.present?
    end
  end
end
