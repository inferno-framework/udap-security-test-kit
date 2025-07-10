module UDAPSecurityTestKit
  class UDAPMetadataEndpointErrorHandlingAttestationTest < Inferno::Test
    title 'Handles unsupported workflows correctly'
    id :udap_security_metadata_error_handling
    description %(
      Server's UDAP metadata endpoint correctly handles unsupported workflows by returning a `404 Not Found` response when no UDAP workflows are supported.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@19'

    input :udap_metadata_error_handling_correct,
          title: "UDAP Metadata and Server Capabilities: Handles unsupported workflows correctly",
          description: %(
            I attest that the server's UDAP metadata endpoint correctly handles unsupported workflows by returning a `404 Not Found` response when no UDAP workflows are supported.
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
    input :udap_metadata_error_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert udap_metadata_error_handling_correct == 'true',
              'Server metadata endpoint did not correctly handle unsupported workflows by returning a `404 Not Found` response.'
      pass udap_metadata_error_handling_note if udap_metadata_error_handling_note.present?
    end
  end
end
