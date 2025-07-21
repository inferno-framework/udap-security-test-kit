module UDAPSecurityTestKit
  class DataHolderAuthRequestScopeAttestationTest < Inferno::Test
    title 'Data Holder Authentication Request Contains `openid` and `udap` Scopes'
    id :udap_security_data_holder_auth_request_scope
    description %(
      Data holder's authentication request to the Identity Provider includes both
      `openid` and `udap` in the `scope` query parameter.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@256'

    input :auth_request_scope_contains_openid_udap,
          title: 'Authentication request `scope` contains `openid` and `udap`',
          description: %(
            I attest that the data holder's authentication request to the Identity Provider includes both
            `openid` and `udap` in the `scope` query parameter.
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
    input :auth_request_scope_contains_openid_udap_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert auth_request_scope_contains_openid_udap == 'true',
             'Authentication request did not include both `openid` and `udap` in the `scope` query parameter.'
      pass auth_request_scope_contains_openid_udap_note if auth_request_scope_contains_openid_udap_note.present?
    end
  end
end
