module UDAPSecurityTestKit
  class DenyTokenRequestAttestationTest < Inferno::Test
    title 'Denies token request that cannot be validated from x5c parameter'
    id :udap_security_deny_token_request
    description %(
      Authorization Server denies the token request if:
      - JWT signature cannot be validated using the public key from the x5c parameter.
      - A trusted certificate chain cannot be built and validated from the x5c parameter.
      - Required parameter is missing or a parameter is invalid.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@174',
                          'hl7.fhir.us.udap-security_1.0.0@176',
                          'hl7.fhir.us.udap-security_1.0.0@183'

    input :deny_token_request,
          title: 'Error Handling: Denies token request that cannot be validated from x5c parameter',
          description: %(
            I attest that the Authorization Server denies the token request if:
            - JWT signature cannot be validated using the public key from the x5c parameter.
            - A trusted certificate chain cannot be built and validated from the x5c parameter.
            - Required parameter is missing or a parameter is invalid.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :deny_token_request_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert deny_token_request == 'true',
             'Authorization Server does not deny the token request when parameter(s) are invalid.'
      pass deny_token_request_note if deny_token_request_note.present?
    end
  end
end
