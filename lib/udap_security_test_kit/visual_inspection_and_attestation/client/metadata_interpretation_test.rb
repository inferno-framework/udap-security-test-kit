module UDAPSecurityTestKit
  class MetadataInterpretationAttestationTest < Inferno::Test
    title 'Client interprets metadata correctly'
    id :udap_security_metadata_interpretation
    description %(
      Client applications SHALL interpret metadata correctly by:
      - Interpreting an empty array value in metadata as indicating that the corresponding capability is NOT supported by the server.
      - Using applicable values returned in a server’s UDAP metadata for workflows defined in this guide.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@20',
                          'hl7.fhir.us.udap-security@21'

    input :interprets_metadata_correctly,
          title: "Interprets metadata correctly",
          description: %(
            I attest that the client application interprets metadata correctly by:
            - Interpreting an empty array value in metadata as indicating that the corresponding capability is NOT supported by the server.
            - Using applicable values returned in a server’s UDAP metadata for workflows defined in this guide.
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
    input :interprets_metadata_correctly_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert interprets_metadata_correctly == 'true',
              'Client application did not demonstrate correct interpretation of metadata.'
      pass interprets_metadata_correctly_note if interprets_metadata_correctly_note.present?
    end
  end
end