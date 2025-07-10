module UDAPSecurityTestKit
  class CommunityParameterSupportAttestationTest < Inferno::Test
    title 'Supports community parameter correctly'
    id :udap_security_community_parameter_support
    description %(
      Server supports the `community` parameter correctly by selecting a certificate intended for use within the
      identified trust community when generating the signed JWT for the `signed_metadata` element.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@62'

    input :community_parameter_support_correct,
          title: 'UDAP Metadata and Server Capabilities: Supports community parameter correctly',
          description: %(
            I attest that the server supports the `community` parameter correctly by selecting a certificate intended
            for use within the identified trust community when generating the signed JWT for the `signed_metadata`
            element.
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
    input :community_parameter_support_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert community_parameter_support_correct == 'true',
             'Server does not correctly support the `community` parameter when generating the signed JWT for the
             `signed_metadata` element.'
      pass community_parameter_support_note if community_parameter_support_note.present?
    end
  end
end
