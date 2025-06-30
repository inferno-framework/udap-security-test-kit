module UDAPSecurityTestKit
  class IdPTokenExchangeAttestationTest < Inferno::Test
    title 'Code is exchanged for tokens after successful authentication response'
    id :udap_security_idp_token_exchange
    description %(
      If the IdP returns a successful authentication response, the Data Holder SHALL exchange the authorization code for tokens.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@279'

    input :idp_token_exchange_correct,
          title: "Code is exchanged for tokens after successful authentication response",
          description: %(
            I attest that the Data Holder exchanges the authorization code for tokens after receiving a successful authentication response from the IdP.
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
    input :idp_token_exchange_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert idp_token_exchange_correct == 'true',
              'Data Holder does not exchange the authorization code for tokens after receiving a successful authentication response from the IdP.'
      pass idp_token_exchange_note if idp_token_exchange_note.present?
    end
  end
end
