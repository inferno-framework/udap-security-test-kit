require_relative '../../lib/udap_security_test_kit/udap_x509_certificate'
require_relative '../../lib/udap_security_test_kit/default_cert_file_loader'

RSpec.describe UDAPSecurityTestKit::UDAPX509Certificate do # rubocop:disable RSpec/SpecFilePathFormat
  let(:ca_cert_string) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_default_ca_pem_file
  end

  let(:ca_private_key_string) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_default_ca_private_key_file
  end

  it 'creates a new client certificate signed by the provided CA' do
    cert = described_class.new(ca_cert_string, ca_private_key_string)

    ca_cert = OpenSSL::X509::Certificate.new(ca_cert_string)

    expect(cert.cert.verify(ca_cert.public_key)).to be true
    expect(cert.cert.extensions).to include(an_object_having_attributes(oid: 'subjectAltName'))
    expect(cert.cert.not_before).to be < Time.now
    expect(cert.cert.not_after).to be > cert.cert.not_before
    expect(cert.cert.not_after).to be > Time.now
    expect(cert.cert.version).to eq 2 # zero-based versioning, so version 3
  end

  it 'does not duplicate serial number or SAN values between instances' do
    cert1 = described_class.new(ca_cert_string, ca_private_key_string)
    cert2 = described_class.new(ca_cert_string, ca_private_key_string)

    expect(cert1.cert.serial == cert2.cert.serial).to be false
    expect(cert1.san == cert2.san).to be false
  end
end
