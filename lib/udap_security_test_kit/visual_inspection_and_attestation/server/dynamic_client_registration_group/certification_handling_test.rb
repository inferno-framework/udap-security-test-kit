module UDAPSecurityTestKit
  class CertificationHandlingAttestationTest < Inferno::Test
    title 'Handles certifications correctly'
    id :udap_security_certification_handling
    description %(
      The Authorization Server handles certifications correctly:
      - Ignores unsupported or unrecognized certifications.
      - Communicates required certifications via the `udap_certifications_required` element in its UDAP metadata.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@116',
                          'hl7.fhir.us.udap-security_1.0.0@118'

    input :certification_handling_correct,
          title: 'Dynamic Client Registration: Handles certifications correctly',
          description: %(
            I attest that the Authorization Server handles certifications correctly:
            - Ignores unsupported or unrecognized certifications.
            - Communicates required certifications via the `udap_certifications_required` element in its UDAP metadata.
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
    input :certification_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert certification_handling_correct == 'true',
             'Authorization Server did not handle certifications correctly.'
      pass certification_handling_note if certification_handling_note.present?
    end
  end
end
