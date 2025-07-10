module UDAPSecurityTestKit
  class TrustCommunityAndQueryParametersAttestationTest < Inferno::Test
    title 'Complies with Trust Community and Query Parameter'
    id :udap_security_trust_community_query_parameters
    description %(
      Client application ensures the value of the `community` query parameter is a valid URI as determined by the trust community.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@61'

    input :community_query_parameter_compliance,
          title: 'Complies with Trust Community and Query Parameter',
          description: %(
            I attest that the client application ensures the value of the `community` query parameter is a valid URI as determined by the trust community.
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
    input :community_query_parameter_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert community_query_parameter_compliance == 'true',
             'Client application did not ensure the `community` query parameter value is a valid URI as determined by the trust community.'
      pass community_query_parameter_compliance_note if community_query_parameter_compliance_note.present?
    end
  end
end
