module UDAPSecurityTestKit
  class IdPAuthenticationComplianceAttestationTest < Inferno::Test
    title 'Identity Provider Authenticates User per OIDC Core and UDAP Tiered OAuth'
    id :udap_security_idp_authentication_compliance
    description %(
      The Identity Provider authenticates the user according to
      [Sections 3.1.2.2 - 3.1.2.6 of OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation)
      and Sections 4.1 - 4.2 of [UDAP Tiered OAuth](https://www.udap.org/udap-user-auth-stu1.html).
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@257'

    input :idp_authenticates_per_spec,
          title: 'IdP authenticates user per OIDC Core and UDAP Tiered OAuth',
          description: %(
            I attest that the Identity Provider authenticates the user according to
            [Sections 3.1.2.2 - 3.1.2.6 of OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation)
            and Sections 4.1 - 4.2 of [UDAP Tiered OAuth](https://www.udap.org/udap-user-auth-stu1.html).
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
    input :idp_authenticates_per_spec_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert idp_authenticates_per_spec == 'true',
             'Identity Provider did not authenticate the user as per OIDC Core and UDAP Tiered OAuth specifications.'
      pass idp_authenticates_per_spec_note if idp_authenticates_per_spec_note.present?
    end
  end
end
