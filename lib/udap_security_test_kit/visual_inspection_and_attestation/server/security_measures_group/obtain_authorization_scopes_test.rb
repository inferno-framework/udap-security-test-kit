module UDAPSecurityTestKit
  class ObtainAuthorizationScopesAttestationTest < Inferno::Test
    title 'Obtains user authorization for requested scopes'
    id :udap_security_user_authorization
    description %(
      Resource Holder, after mapping the authenticated user, obtains authorization from the user for the scopes
      requested by the client app, if such authorization is required, as per Section [4.5 of UDAP Tiered OAuth](https://www.udap.org/udap-user-auth-stu1.html),
      returning to the workflow defined in [Section 4.1](https://hl7.org/fhir/us/udap-security/STU1/consumer.html#obtaining-an-authorization-code)
      or [Section 5.1](https://hl7.org/fhir/us/udap-security/STU1/b2b.html#obtaining-an-authorization-code) of this
      guide, for consumer-facing or B2B apps, respectively.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@297'

    input :user_authorization_correct,
          title: 'Security Measures: Obtains user authorization for requested scopes',
          description: %(
            I attest that the Resource Holder, after mapping the authenticated user, obtains authorization from the
            user for the scopes requested by the client app, if such authorization is required, as per Section
            [4.5 of UDAP Tiered OAuth](https://www.udap.org/udap-user-auth-stu1.html), returning to the workflow
            defined in [Section 4.1](https://hl7.org/fhir/us/udap-security/STU1/consumer.html#obtaining-an-authorization-code)
            or [Section 5.1](https://hl7.org/fhir/us/udap-security/STU1/b2b.html#obtaining-an-authorization-code) of
            this guide, for consumer-facing or B2B apps, respectively.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :user_authorization_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert user_authorization_correct == 'true',
             'Resource Holder does not obtain user authorization for the requested scopes after mapping the
              authenticated user.'
      pass user_authorization_note if user_authorization_note.present?
    end
  end
end
