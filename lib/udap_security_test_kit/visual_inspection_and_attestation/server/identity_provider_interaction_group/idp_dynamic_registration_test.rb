module UDAPSecurityTestKit
  class IdPDynamicRegistrationAttestationTest < Inferno::Test
    title 'Performs IdP dynamic registration if supported'
    id :udap_security_idp_dynamic_registration
    description %(
      Data Holder registers as a client with the IdP if:
      - The IdP is trusted.
      - The IdP supports UDAP Dynamic Registration.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@239'

    input :idp_dynamic_registration_correct,
          title: 'Interaction with Identity Providers (IdPs): Performs IdP dynamic registration if supported',
          description: %(
            I attest that the Data Holder registers as a client with the IdP if:
            - The IdP is trusted.
            - The IdP supports UDAP Dynamic Registration.
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
    input :idp_dynamic_registration_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert idp_dynamic_registration_correct == 'true',
             'Data Holder does not register as a client with the IdP when it is trusted and supports
              UDAP Dynamic Registration.'
      pass idp_dynamic_registration_note if idp_dynamic_registration_note.present?
    end
  end
end
