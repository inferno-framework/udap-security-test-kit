module UDAPSecurityTestKit
  class ScopesAndIdentityProviderInteractionAttestationTest < Inferno::Test
    title 'Complies with Scopes and Identity Provider Interaction'
    id :udap_security_scopes_identity_provider_interaction
    description %(
      Client applications complies with the requirements for Scopes and Identity Provider Interaction:
      - Client application includes `udap` in the list of scopes provided in the `scope` query
        parameter to indicate the preferred Identity Provider.
      - Client application authenticates the user according to the OIDC Core and UDAP Tiered OAuth specifications.
      - Identity Provider authenticates the user according to the OIDC Core and UDAP Tiered OAuth specifications.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@236',
                          'hl7.fhir.us.udap-security_1.0.0@256',
                          'hl7.fhir.us.udap-security_1.0.0@257'

    input :scope_includes_udap,
          title: 'Includes `udap` in the `scope` query parameter',
          description: %(
            I attest that the client application includes `udap` in the list of scopes provided in the `scope` query
            parameter to indicate the preferred Identity Provider.
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
          title: 'Ensures `scope` query parameter contains `openid` and `udap`',
          description: %(
            I attest that the client application ensures the `scope` query parameter of the authentication request
            contains at least the values `openid` and `udap`.
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
          title: 'Authenticates user as per OIDC Core and UDAP Tiered OAuth specifications',
          description: %(
            I attest that the Identity Provider authenticates the user according to the OIDC Core and UDAP Tiered
            OAuth specifications.
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
             'Client application did not include `udap` in the `scope` query parameter to indicate the preferred
             Identity Provider.'
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
