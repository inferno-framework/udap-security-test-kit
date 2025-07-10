module UDAPSecurityTestKit
  class SoftwareStatementAndRegistrationAttestationTest < Inferno::Test
    title 'Complies with Software Statement and Registration'
    id :udap_security_software_statement_registration
    description %(
      Client complies with the requirements for Software Statement and Registration:
      - Ensures that the `jti` claim in the JWT is not reused in another software statement or authentication JWT before the time specified in the `exp` claim has passed.
      - Interprets a registration response containing an empty `grant_types` array as a confirmation that the registration for the `client_id` listed in the response has been cancelled by the Authorization Server.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@82',
                          'hl7.fhir.us.udap-security_1.0.0@123'

    input :jti_reuse_compliance,
          title: "Ensures that the `jti` claim in the JWT is not reused before the `exp` claim has passed",
          description: %(
            I attest that the client application ensures that the `jti` claim in the JWT is not reused in another software statement or authentication JWT before the time specified in the `exp` claim has passed.
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
    input :jti_reuse_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    input :grant_types_empty_array_compliance,
          title: "Interprets empty `grant_types` array as registration cancellation",
          description: %(
            I attest that the client application interprets a registration response containing an empty `grant_types` array as a confirmation that the registration for the `client_id` listed in the response has been cancelled by the Authorization Server.
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
    input :grant_types_empty_array_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert jti_reuse_compliance == 'true',
             'Client application reused the `jti` claim before the `exp` claim has passed.'
      pass jti_reuse_compliance_note if jti_reuse_compliance_note.present?

      assert grant_types_empty_array_compliance == 'true',
             'Client application did not interpret an empty `grant_types` array as registration cancellation.'
      pass grant_types_empty_array_compliance_note if grant_types_empty_array_compliance_note.present?
    end
  end
end
