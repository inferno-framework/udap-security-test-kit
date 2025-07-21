module UDAPSecurityTestKit
  class AuthorizationCodeFlowAttestationTest < Inferno::Test
    title 'Resource Holder uses the authorization code flow'
    id :udap_security_authorization_code_flow
    description %(
      The Resource Holder uses the authorization code flow when redirecting the user
      to the IdP’s authorization endpoint.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@253'

    input :authorization_code_flow_correct,
          title: 'Authorization Code and Token Requests: Resource Holder uses authorization code flow',
          description: %(
            I attest that the Resource Holder uses the authorization code flow when redirecting
            the user to the IdP’s authorization endpoint.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :authorization_code_flow_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert authorization_code_flow_correct == 'true',
             'Resource Holder does not use the authorization code flow when redirecting the user to the
             IdP’s authorization endpoint.'
      pass authorization_code_flow_note if authorization_code_flow_note.present?
    end
  end
end
