module UDAPSecurityTestKit
  class JwtJtiReuseAttestationTest < Inferno::Test
    title 'Does not reuse JWT `jti` value before expiry'
    id :udap_security_jwt_jti_reuse
    description %(
      The server does not reuse a `jti` value in another JWT before the time specified in the `exp` claim has passed.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@56'

    input :jwt_jti_reuse_correct,
          title: 'JWT/Token Validation and Security: Does not reuse JWT `jti` value before expiry',
          description: %(
            I attest that the server does not reuse a `jti` value in another JWT before the time specified in the `exp`
            claim has passed.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :jwt_jti_reuse_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert jwt_jti_reuse_correct == 'true',
             'The server reuses a `jti` value in another JWT before the `exp` time has passed.'
      pass jwt_jti_reuse_note if jwt_jti_reuse_note.present?
    end
  end
end
