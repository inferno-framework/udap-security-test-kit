module UDAPSecurityTestKit
  class DynamicClientRegistrationValidationAttestationTest < Inferno::Test
    title 'Dynamic Client Registration request is validated correctly'
    id :udap_security_dynamic_client_registration_validation
    description %(
      The Authorization Server SHALL validate dynamic client registration requests by:
      - Ensuring the `sub` value matches the `iss` value.
      - Ensuring the `aud` value contains the Authorization Server’s registration endpoint URL.
      - Ensuring the software statement is unexpired.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@107',
                          'hl7.fhir.us.udap-security@108',
                          'hl7.fhir.us.udap-security@109'

    input :dynamic_client_registration_validation_correct,
          title: "Dynamic Client Registration request is validated correctly",
          description: %(
            I attest that the Authorization Server validates dynamic client registration requests by:
            - Ensuring the `sub` value matches the `iss` value.
            - Ensuring the `aud` value contains the Authorization Server’s registration endpoint URL.
            - Ensuring the software statement is unexpired.
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
    input :dynamic_client_registration_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert dynamic_client_registration_validation_correct == 'true',
              'Authorization Server did not validate dynamic client registration requests correctly.'
      pass dynamic_client_registration_validation_note if dynamic_client_registration_validation_note.present?
    end
  end
end
