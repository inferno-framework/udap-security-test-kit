module UDAPSecurityTestKit
  class IdPAuthenticationRequestAttestationTest < Inferno::Test
    title 'Authentication request is made to the IdP’s authorization endpoint'
    id :udap_security_idp_authentication_request
    description %(
      If the IdP is trusted, the Data Holder SHALL make an authentication request to the IdP’s authorization endpoint.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@245'

    input :idp_authentication_request_correct,
          title: "Authentication request is made to the IdP’s authorization endpoint",
          description: %(
            I attest that the Data Holder makes an authentication request to the IdP’s authorization endpoint when the IdP is trusted.
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
    input :idp_authentication_request_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert idp_authentication_request_correct == 'true',
              'Data Holder does not make an authentication request to the IdP’s authorization endpoint when the IdP is trusted.'
      pass idp_authentication_request_note if idp_authentication_request_note.present?
    end
  end
end
