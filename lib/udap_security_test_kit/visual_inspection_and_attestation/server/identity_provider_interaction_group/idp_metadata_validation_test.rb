module UDAPSecurityTestKit
  class IdPMetadataValidationAttestationTest < Inferno::Test
    title 'IdP metadata is validated to determine trust'
    id :udap_security_idp_metadata_validation
    description %(
      The Data Holder SHALL validate the IdP’s UDAP metadata to determine trustworthiness before interacting with the IdP.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@238'

    input :idp_metadata_validation_correct,
          title: "IdP metadata is validated to determine trust",
          description: %(
            I attest that the Data Holder validates the IdP’s UDAP metadata to determine trustworthiness, including:
            - Verifying the authenticity of the metadata.
            - Ensuring the metadata meets UDAP specifications.
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
    input :idp_metadata_validation_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert idp_metadata_validation_correct == 'true',
              'Data Holder does not validate the IdP’s UDAP metadata to determine trustworthiness.'
      pass idp_metadata_validation_note if idp_metadata_validation_note.present?
    end
  end
end
