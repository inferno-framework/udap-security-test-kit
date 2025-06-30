module UDAPSecurityTestKit
  class TrustCommunityAndQueryParametersAttestationTest < Inferno::Test
    title 'Trust Community and Query Parameters Compliance'
    id :udap_security_trust_community_query_parameters
    description %(
      Client applications SHALL comply with the requirements for Trust Community and Query Parameters:
      - When the client adds the `community` query parameter, the value SHALL be a URI as determined by the trust community.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@61'

    input :community_query_parameter_compliance,
          title: "Client application ensures `community` query parameter value is a valid URI",
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
