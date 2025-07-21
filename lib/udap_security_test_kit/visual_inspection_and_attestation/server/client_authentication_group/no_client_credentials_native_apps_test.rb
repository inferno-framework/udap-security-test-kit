module UDAPSecurityTestKit
  class NoClientCredentialsForNativeAppsAttestationTest < Inferno::Test
    title 'Does not issue client credentials to native/user-agent-based apps'
    id :udap_security_no_client_credentials_native_apps
    description %(
      The Authorization Server does not issue client passwords or other client
      credentials to native application or user-agent-based application clients for the
      purpose of client authentication.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@287'

    input :no_client_credentials_native_apps_correct,
          title: 'Client Authentication: Does not issue client credentials to native/user-agent-based apps',
          description: %(
            I attest that the Authorization Server does not issue client passwords or other client
            credentials to native application or user-agent-based application clients for the
            purpose of client authentication.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :no_client_credentials_native_apps_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert no_client_credentials_native_apps_correct == 'true',
             'Authorization Server issues client credentials to native or user-agent-based application clients.'
      pass no_client_credentials_native_apps_note if no_client_credentials_native_apps_note.present?
    end
  end
end
