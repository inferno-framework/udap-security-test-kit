module UDAPSecurityTestKit
  class UDAPMetadataEndpointErrorHandlingAttestationTest < Inferno::Test
    title 'UDAP Metadata endpoint correctly handles unsupported workflows'
    id :udap_security_metadata_error_handling
    description %(
      If no UDAP workflows are supported, the server SHALL return a `404 Not Found` response to the metadata request.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@19'

    input :udap_metadata_error_handling_correct,
          title: "UDAP Metadata endpoint correctly handles unsupported workflows",
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
