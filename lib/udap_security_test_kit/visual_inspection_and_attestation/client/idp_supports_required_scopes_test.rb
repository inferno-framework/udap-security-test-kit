module UDAPSecurityTestKit
  class IdPSupportsRequiredScopesAttestationTest < Inferno::Test
      title 'IdP supports required scopes'
      id :udap_security_idp_supports_scopes
      description %(
        Identity Providers (IdPs) SHALL include `"openid"` and `"udap"` in the array of scopes returned for the `scopes_supported` parameter.
      )
      verifies_requirements 'hl7.fhir.us.udap-security@235'

      input :idp_supports_required_scopes,
            title: "IdP supports required scopes",
            description: %(
              I attest that the Identity Provider (IdP) includes `"openid"` and `"udap"` in the array of scopes returned for the `scopes_supported` parameter.
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
      input :idp_supports_required_scopes_note,
            title: 'Notes, if applicable:',
            type: 'textarea',
            optional: true

      run do
        assert idp_supports_required_scopes == 'true',
               'Identity Provider (IdP) did not demonstrate support for required scopes.'
        pass idp_supports_required_scopes_note if idp_supports_required_scopes_note.present?
      end
  end
end