module UDAPSecurityTestKit
  class PromptNoneErrorAttestationTest < Inferno::Test
    title 'Returns error for prompt=none when user not authenticated'
    id :udap_security_prompt_none_error
    description %(
      Authorization Server returns an error if the authentication request contains prompt=none
      and the End-User is not already authenticated or could not be silently authenticated.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@267',
                          'hl7.fhir.us.udap-security_1.0.0@268'

    input :prompt_none_error_handling_correct,
          title: 'Error Handling: Returns error for prompt=none when user not authenticated',
          description: %(
            I attest that the Authorization Server returns an error if the authentication
            request contains prompt=none and the End-User is not already authenticated or
            could not be silently authenticated.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :prompt_none_error_handling_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert prompt_none_error_handling_correct == 'true',
             'Authorization Server does not return an error for prompt=none when the End-User
              is not authenticated or could not be silently authenticated.'
      pass prompt_none_error_handling_note if prompt_none_error_handling_note.present?
    end
  end
end
