require_relative '../../lib/udap_security/signed_metadata_trust_verification_test'
require_relative '../../lib/udap_security/udap_jwt_builder'
require_relative '../../lib/udap_security/default_cert_file_loader'

RSpec.describe UDAPSecurity::SignedMetadataTrustVerificationTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_signed_metadata_trust_verification') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }

  let(:client_cert) do
    UDAPSecurity::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:root_ca) do
    UDAPSecurity::DefaultCertFileLoader.load_default_ca_pem_file
  end

  let(:invalid_trust_anchor) do
    root_key = OpenSSL::PKey::RSA.new 2048
    root_ca = OpenSSL::X509::Certificate.new
    root_ca.version = 2
    root_ca.serial = 1
    root_ca.subject = OpenSSL::X509::Name.parse 'C=US/ST=MA/L=Bedford/O=Inferno/CN=Inferno-Invalid-UDAP-Test-CA/'
    root_ca.issuer = root_ca.subject
    root_ca.public_key = root_key.public_key
    root_ca.not_before = Time.now
    root_ca.not_after = root_ca.not_before + (2 * 365 * 24 * 60 * 60)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = root_ca
    ef.issuer_certificate = root_ca
    root_ca.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
    root_ca.add_extension(ef.create_extension('keyUsage', 'keyCertSign, cRLSign', true))
    root_ca.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash', false))
    root_ca.add_extension(ef.create_extension('authorityKeyIdentifier', 'keyid:always', false))
    root_ca.sign(root_key, OpenSSL::Digest.new('SHA256'))
    root_ca.to_pem
  end

  let(:signing_algorithm) { 'RS256' }

  let(:mock_crl_endpoint) { 'https://inferno.com/mock_crl_endpoint.crl' }

  let(:inferno_crl) do
    File.read(File.join(File.dirname(__FILE__), '../../spec/fixtures/crl/InfernoCA_CRL.pem'))
  end

  # Occurs when full cert chain provided in x5c header but chain's root CA not
  # set as a trust anchor
  # Algorithm encounters a self-signed cert (the root CA), ending the chain,
  # but no certs have matched a trusted source yet
  let(:self_signed_cert_error) { /self.signed certificate in certificate chain/ }

  # Occurs when the issuing cert of a cert in the chain being verified is not
  # on hand
  # E.g., client cert is in chain but system does not have access to
  # intermediate CA
  # Or, intermediate CA is in chain but system does not have access to root CA
  let(:missing_cert_error) { /unable to get local issuer certificate/ }

  def run(runnable, inputs = {})
    test_run_params = { test_session_id: test_session.id }.merge(runnable.reference_hash)
    test_run = Inferno::Repositories::TestRuns.new.create(test_run_params)
    inputs.each do |name, value|
      session_data_repo.save(
        test_session_id: test_session.id,
        name:,
        value:,
        type: runnable.config.input_type(name)
      )
    end
    Inferno::TestRunner.new(test_session:, test_run:).run(runnable)
  end

  def create_test_jwt(include_root_ca: true)
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    x5c_certs = [client_cert]
    x5c_certs.append(root_ca) if include_root_ca
    UDAPSecurity::UDAPJWTBuilder.encode_jwt_with_x5c_header(
      {},
      rsa_private.to_pem,
      signing_algorithm,
      x5c_certs
    )
  end

  context 'when no trust anchor certificates are provided as inputs' do
    it 'skips the test' do
      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: '')
      expect(result.result).to eq('skip')
    end
  end

  context 'when JWT includes client and root certs' do
    it 'passes when only root CA provided as trust anchor' do
      stub_request(:get, mock_crl_endpoint)
        .to_return(status: 200, body: inferno_crl)

      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: root_ca)
      expect(result.result).to eq('pass')
    end

    it 'passes when both client and root CAs provided as trust anchor' do
      stub_request(:get, mock_crl_endpoint)
        .to_return(status: 200, body: inferno_crl)

      trust_anchors = "#{root_ca},#{client_cert}"
      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: trust_anchors)
      expect(result.result).to eq('pass')
    end

    it 'fails when client cert not root CA is provided as trust anchor' do
      stub_request(:get, mock_crl_endpoint)
        .to_return(status: 200, body: inferno_crl)

      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: client_cert)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(self_signed_cert_error)
    end

    it 'fails when incorrect root CA is provided as trust anchor' do
      stub_request(:get, mock_crl_endpoint)
        .to_return(status: 200, body: inferno_crl)

      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: invalid_trust_anchor)
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(self_signed_cert_error)
    end
  end

  context 'when JWT includes only client cert' do
    it 'fails when incorrect root CA is provided as trust anchor' do
      stub_request(:get, mock_crl_endpoint)
        .to_return(status: 200, body: inferno_crl)

      result = run(runnable,
                   signed_metadata_jwt: create_test_jwt(include_root_ca: false),
                   udap_server_trust_anchor_certs: invalid_trust_anchor)
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(missing_cert_error)
    end

    it 'passes when only root CA provided as trust anchor' do
      stub_request(:get, mock_crl_endpoint)
        .to_return(status: 200, body: inferno_crl)

      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: root_ca)
      expect(result.result).to eq('pass')
    end
  end
end
