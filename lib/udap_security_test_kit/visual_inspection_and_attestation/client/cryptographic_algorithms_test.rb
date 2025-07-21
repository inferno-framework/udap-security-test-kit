module UDAPSecurityTestKit
  class CryptographicAlgorithmsAndSecurityProtocolsAttestationTest < Inferno::Test
    title 'supports the RS256 signature algorithm'
    id :udap_security_crypto_algorithms_and_protocols
    description %(
      Client application supports the RS256 signature algorithm as defined in as defined in
      [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1) for UDAP workflows.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@4'

    input :crypto_algorithms_and_protocols_compliance,
          title: 'Supports the RS256 signature algorithm',
          description: %(
            I attest that the client application supports the RS256 signature algorithm as defined in as defined in
            [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1) for UDAP workflows.
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

    input :crypto_algorithms_and_protocols_compliance_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert crypto_algorithms_and_protocols_compliance == 'true',
             'Client application did not comply with cryptographic algorithms and security protocols requirements
              (RS256 support).'
      pass crypto_algorithms_and_protocols_compliance_note if crypto_algorithms_and_protocols_compliance_note.present?
    end
  end
end
