module UDAPSecurityTestKit
  class UDAPMetadataRepresentationAttestationTest < Inferno::Test
    title 'Represents server capabilities correctly'
    id :udap_security_metadata_representation
    description %(
      Server's UDAP metadata endpoint correctly represents the server’s capabilities with respect to the UDAP
      workflows described in the guide.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@18'

    input :udap_metadata_representation_correct,
          title: 'UDAP Metadata and Server Capabilities: Represents server capabilities correctly',
          description: %(
            I attest that the server's UDAP metadata endpoint correctly represents the server’s capabilities with
            respect to the UDAP workflows described in the guide.
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
    input :udap_metadata_representation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert udap_metadata_representation_correct == 'true',
             'Server metadata does not correctly represent the server’s capabilities with respect to UDAP workflows.'
      pass udap_metadata_representation_note if udap_metadata_representation_note.present?
    end
  end
end
