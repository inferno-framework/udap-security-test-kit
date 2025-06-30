module UDAPSecurityTestKit
  class ValidationAndConfidentialityAttestationTest < Inferno::Test
    title 'Validation and Confidentiality Compliance'
    id :udap_security_validation_confidentiality
    description %(
      Client applications SHALL comply with the requirements for Validation and Confidentiality:
      - Validate the `state` parameter returned by the Resource Holder in response to an authorization request.
      - Ensure confidentiality of client passwords and other client credentials.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@274',
                          'hl7.fhir.us.udap-security@286'

    input :state_parameter_validation,
          title: "Client application validates the `state` parameter returned by the Resource Holder",
          description: %(
            I attest that the client application validates the `state` parameter returned by the Resource Holder in response to an authorization request to ensure it matches the value sent in the original request.
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
    input :state_parameter_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    input :client_credentials_confidentiality,
          title: "Client application ensures confidentiality of client passwords and credentials",
          description: %(
            I attest that the client application ensures confidentiality of client passwords and other client credentials by securely storing and transmitting them.
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
    input :client_credentials_confidentiality_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert state_parameter_validation == 'true',
             'Client application did not validate the `state` parameter returned by the Resource Holder.'
      pass state_parameter_validation_note if state_parameter_validation_note.present?

      assert client_credentials_confidentiality == 'true',
             'Client application did not ensure confidentiality of client passwords and other client credentials.'
      pass client_credentials_confidentiality_note if client_credentials_confidentiality_note.present?
    end
  end
end
