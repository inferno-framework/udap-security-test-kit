module UDAPSecurityTestKit
  class SoftwareStatementAndRegistrationAttestationTest < Inferno::Test
    title 'Complies with Software Statement and Registration'
    id :udap_security_software_statement_registration
    description %(
      Client application complies with the requirements for Software Statement and Registration:
      - Ensures that the `jti` claim in the JWT is not reused in another software statement or authentication JWT
        before the time specified in the `exp` claim has passed.
      - Interprets a registration response containing an empty `grant_types` array as a confirmation that the
        registration for the `client_id` listed in the response has been cancelled by the Authorization Server.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@82',
                          'hl7.fhir.us.udap-security_1.0.0@123'

    input :software_statement_registration_compliance,
          title: 'Complies with the requirements for Software Statement and Registration',
          description: %(
            I attest that the client application complies with the requirements for Software Statement and Registration:
            - Ensures that the `jti` claim in the JWT is not reused in another software statement or authentication JWT
              before the time specified in the `exp` claim has passed.
            - Interprets a registration response containing an empty `grant_types` array as a confirmation that the
              registration for the `client_id` listed in the response has been cancelled by the Authorization Server.
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
    input :software_statement_registration_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert software_statement_registration_compliance == 'true',
             'Client application did not comply with the requirements for Software Statement and Registration.'
      pass software_statement_registration_compliance_note if software_statement_registration_compliance_note.present?
    end
  end
end
