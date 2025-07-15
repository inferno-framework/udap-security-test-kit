module UDAPSecurityTestKit
  class B2BAuthorizationExtensionObjectAttestationTest < Inferno::Test
    title 'Complies with B2B Authorization Extension Object'
    id :udap_security_b2b_authorization_extension_object
    description %(
      Client applications complies with requirements for the B2B Authorization Extension Object and:
      - Includes `subject_name` parameter if it is known for human or non-human requestors.
      - Includes `subject_id` parameter for human requestors when the `subject_name` parameter is present.
      - Uses the National Provider Identifier (NPI) as the value for `subject_id` for human requestors in the US Realm.
      - Ensures that the `consent_reference` parameter includes URLs that are resolvable by the receiving party
      - Omits `consent_reference` if `consent_policy` is not present.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@203',
                          'hl7.fhir.us.udap-security_1.0.0@204',
                          'hl7.fhir.us.udap-security_1.0.0@205',
                          'hl7.fhir.us.udap-security_1.0.0@206',
                          'hl7.fhir.us.udap-security_1.0.0@207',
                          'hl7.fhir.us.udap-security_1.0.0@219',
                          'hl7.fhir.us.udap-security_1.0.0@220',
                          'hl7.fhir.us.udap-security_1.0.0@221'

    input :b2b_authorization_extension_object_compliance,
          title: 'Complies with requirements for the B2B Authorization Extension Object',
          description: %(
            I attest that the client applications complies with requirements for the B2B Authorization Extension Object
            and:
            - Includes `subject_name` parameter if it is known for human or non-human requestors.
            - Includes `subject_id` parameter for human requestors when the `subject_name` parameter is present.
            - Uses the National Provider Identifier (NPI) as the value for `subject_id` for human requestors in the US
              Realm.
            - Ensures that the `consent_reference` parameter includes URLs that are resolvable by the receiving party
            - Omits `consent_reference` if `consent_policy` is not present.
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
    input :b2b_authorization_extension_object_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert b2b_authorization_extension_object_compliance == 'true',
             'Client application did not comply with requirements for the B2B Authorization Extension Object.'
      if b2b_authorization_extension_object_compliance_note.present?
        pass b2b_authorization_extension_object_compliance_note
      end
    end
  end
end
