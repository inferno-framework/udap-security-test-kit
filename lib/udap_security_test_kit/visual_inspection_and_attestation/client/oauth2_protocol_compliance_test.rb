module UDAPSecurityTestKit
  class OAuth2ProtocolComplianceAttestationTest < Inferno::Test
    title 'Complies with OAuth 2.0 Protocol Requirements'
    id :udap_security_oauth2_protocol_compliance
    description %(
      Client application complies with OAuth 2.0 protocol requirements:
      - Ignores unrecognized response parameters in the authorization response when receiveing an response to an
        authorization request.
      - Follows the token request and response protocol as defined in RFC 6749 Sections 4.1.3 and 4.1.4 when
        authenticating with a shared secret.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@139',
                          'hl7.fhir.us.udap-security_1.0.0@162'

    input :oauth2_protocol_compliance,
          title: 'Complies with OAuth 2.0 Protocol Requirements',
          description: %(
            I attest that the client application complies with OAuth 2.0 protocol requirements:
            - Ignores unrecognized response parameters in the authorization response when receiveing an response to an
              authorization request.
            - Follows the token request and response protocol as defined in RFC 6749 Sections 4.1.3 and 4.1.4 when
              authenticating with a shared secret.
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

    input :oauth2_protocol_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert oauth2_protocol_compliance == 'true',
             'Client application did not comply with OAuth 2.0 protocol requirements.'
      pass oauth2_protocol_compliance_note if oauth2_protocol_compliance_note.present?
    end
  end
end
