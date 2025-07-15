module UDAPSecurityTestKit
  class ValidationAndConfidentialityAttestationTest < Inferno::Test
    title 'Complies with Validation and Confidentiality'
    id :udap_security_validation_confidentiality
    description %(
      Client applications complies with the requirements for Validation and Confidentiality:
      - Validates the `state` parameter returned by the Resource Holder in response to an authorization request to
        ensure it matches the value sent in the original request.
      - Ensures confidentiality of client passwords and other client credentials by securely storing and
        transmitting them.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@274',
                          'hl7.fhir.us.udap-security_1.0.0@286'

    input :validation_confidentiality_compliance,
          title: 'Complies with requirements for Validation and Confidentiality',
          description: %(
            I attest that the client applications complies with the requirements for Validation and Confidentiality:
            - Validates the `state` parameter returned by the Resource Holder in response to an authorization request to
              ensure it matches the value sent in the original request.
            - Ensures confidentiality of client passwords and other client credentials by securely storing and
              transmitting them.
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
    input :validation_confidentiality_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert validation_confidentiality_compliance == 'true',
             'Client application did not validate the `state` parameter returned by the Resource Holder.'
      pass validation_confidentiality_compliance_note if validation_confidentiality_compliance_note.present?
    end
  end
end
