module UDAPSecurityTestKit
  class ClientCertificateStorageAttestationTest < Inferno::Test
    title 'Authorization Server stores client certificate for authentication'
    id :udap_security_client_certificate_storage
    description %(
      The Authorization Server stores the certificate provided by the Client for
      use in validating subsequent client authentication attempts.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@112'

    input :client_certificate_storage_correct,
          title: 'Client Authentication: Authorization Server stores client certificate',
          description: %(
            I attest that the Authorization Server stores the certificate provided by the Client for
            use in validating subsequent client authentication attempts.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              { label: 'Yes', value: 'true' },
              { label: 'No', value: 'false' }
            ]
          }
    input :client_certificate_storage_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert client_certificate_storage_correct == 'true',
             'Authorization Server does not store the client certificate for use in subsequent authentication attempts.'
      pass client_certificate_storage_note if client_certificate_storage_note.present?
    end
  end
end
