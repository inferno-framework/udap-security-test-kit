module UDAPSecurityTestKit
  class JTIReusePreventionAttestationTest < Inferno::Test
    title 'Client prevents reuse of JTI values in authentication tokens'
    id :udap_security_jti_reuse_prevention
    description %(
      Client applications SHALL prevent reuse of JTI values in authentication tokens by:
      - Ensuring the `jti` parameter is not reused in another authentication JWT before the time specified in the `exp` claim has passed.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@159'

    input :jti_reuse_prevention_correctly,
          title: "Client prevents reuse of JTI values in authentication tokens",
          description: %(
            I attest that the client application prevents reuse of JTI values in authentication tokens by:
            - Ensuring the `jti` parameter is not reused in another authentication JWT before the time specified in the `exp` claim has passed.
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
    input :jti_reuse_prevention_correctly_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert jti_reuse_prevention_correctly == 'true',
              'Client application did not demonstrate prevention of JTI reuse in authentication tokens.'
      pass jti_reuse_prevention_correctly_note if jti_reuse_prevention_correctly_note.present?
    end
  end
end
