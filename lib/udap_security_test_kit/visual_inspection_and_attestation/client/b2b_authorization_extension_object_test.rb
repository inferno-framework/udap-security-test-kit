module UDAPSecurityTestKit
  class B2BAuthorizationExtensionObjectAttestationTest < Inferno::Test
    title 'B2B Authorization Extension Object Compliance'
    id :udap_security_b2b_authorization_extension_object
    description %(
      Client applications SHALL comply with the requirements for the B2B Authorization Extension Object:
      - `subject_name` SHALL be required if known for human or non-human requestors.
      - `subject_id` SHALL be required if known for human requestors when `subject_name` is present.
      - `subject_id` SHALL be the National Provider Identifier (NPI) for US Realm human requestors.
      - `subject_id` SHALL be omitted for non-human requestors or requestors without an NPI.
      - `consent_reference` SHALL include resolvable URLs and SHALL be omitted if `consent_policy` is not present.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@203',
                          'hl7.fhir.us.udap-security@204',
                          'hl7.fhir.us.udap-security@205',
                          'hl7.fhir.us.udap-security@206',
                          'hl7.fhir.us.udap-security@207',
                          'hl7.fhir.us.udap-security@219',
                          'hl7.fhir.us.udap-security@220',
                          'hl7.fhir.us.udap-security@221'

    input :subject_name_compliance,
          title: "Client application includes `subject_name` if known",
          description: %(
            I attest that the client application includes the `subject_name` parameter if it is known for human or non-human requestors.
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
    input :subject_name_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    input :subject_id_compliance,
          title: "Client application includes `subject_id` for human requestors when `subject_name` is present",
          description: %(
            I attest that the client application includes the `subject_id` parameter for human requestors when the `subject_name` parameter is present.
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
    input :subject_id_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    input :subject_id_npi_compliance,
          title: "Client application uses NPI for `subject_id` in US Realm human requestors",
          description: %(
            I attest that the client application uses the National Provider Identifier (NPI) as the value for `subject_id` for human requestors in the US Realm.
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
    input :subject_id_npi_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    input :consent_reference_compliance,
          title: "Client application ensures `consent_reference` URLs are resolvable",
          description: %(
            I attest that the client application ensures that the `consent_reference` parameter includes URLs that are resolvable by the receiving party and omits `consent_reference` if `consent_policy` is not present.
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
    input :consent_reference_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert subject_name_compliance == 'true',
             'Client application did not include `subject_name` when it was known.'
      pass subject_name_compliance_note if subject_name_compliance_note.present?

      assert subject_id_compliance == 'true',
             'Client application did not include `subject_id` for human requestors when `subject_name` was present.'
      pass subject_id_compliance_note if subject_id_compliance_note.present?

      assert subject_id_npi_compliance == 'true',
             'Client application did not use NPI for `subject_id` for human requestors in the US Realm.'
      pass subject_id_npi_compliance_note if subject_id_npi_compliance_note.present?

      assert consent_reference_compliance == 'true',
             'Client application did not ensure `consent_reference` URLs were resolvable or omitted `consent_reference` when `consent_policy` was not present.'
      pass consent_reference_compliance_note if consent_reference_compliance_note.present?
    end
  end
end
