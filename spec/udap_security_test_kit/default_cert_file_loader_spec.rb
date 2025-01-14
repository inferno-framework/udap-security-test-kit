require_relative '../../lib/udap_security_test_kit/default_cert_file_loader'
require_relative '../../lib/udap_security_test_kit/udap_jwt_builder'
require_relative '../../lib/udap_security_test_kit/software_statement_builder'

RSpec.describe UDAPSecurityTestKit::DefaultCertFileLoader do
  it 'loads the SureFhir private key' do
    private_key = described_class.load_specified_private_key('SureFhir')
  end

  it 'loads the EMRDirect private key' do
    private_key = described_class.load_specified_private_key('EMRDirect')

    raw_cert = File.read('/Users/awallace/Desktop/test_certs/jan-2025-connectathon/phimail-credentials/emr-direct-certs/EMRDirectClientCert.pem')
    cert = OpenSSL::X509::Certificate.new raw_cert

    expect(cert.check_private_key(private_key)).to be true

    # payload = { 'test_key' => 'test_value' }

    # encoded_jwt = UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header_no_string_pkey(payload, private_key,
    #                                                                                             'RS256', [cert.to_pem])

    # puts encoded_jwt
    software_statement_payload = UDAPSecurityTestKit::SoftwareStatementBuilder.build_payload(
      'https://inferno.healthit.gov',
      'https://udap-security.fast.hl7.org/connect/register',
      'authorization_code',
      'patient/*.read'
    )

    encoded_jwt = UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header_no_string_pkey(software_statement_payload, private_key,
                                                                                                'RS256', [cert.to_pem])
    puts encoded_jwt
  end
end
