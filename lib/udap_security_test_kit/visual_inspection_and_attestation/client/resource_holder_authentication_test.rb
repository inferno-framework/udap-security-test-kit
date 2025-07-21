module UDAPSecurityTestKit
  class ResourceHolderTokenEndpointAuthenticationAttestationTest < Inferno::Test
    title 'Authenticates to IdP Token Endpoint'
    id :udap_security_resource_holder_token_endpoint_authentication
    description %(
      The Resource authenticates to the IdP’s token endpoint when requesting an ID token
      and access token, as detailed in Section 5 of UDAP JWT-based Client Authentication.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@281'

    input :resource_holder_token_endpoint_authentication,
          title: 'Authenticates to IdP Token Endpoint',
          description: %(
            I attest that the Resource Holder authenticates to the IdP’s token endpoint when requesting an ID token
            and access token, as detailed in Section 5 of UDAP JWT-based Client Authentication.
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

    input :resource_holder_token_endpoint_authentication_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert resource_holder_token_endpoint_authentication == 'true',
             'Resource Holder did not authenticate to the IdP’s token endpoint as required.'
      if resource_holder_token_endpoint_authentication_note.present?
        pass resource_holder_token_endpoint_authentication_note
      end
    end
  end
end
