require_relative '../../lib/udap_security/signed_metadata_trust_verification_test'
require_relative '../../lib/udap_security/udap_jwt_builder'
require_relative '../../lib/udap_security/default_cert_file_loader'

RSpec.describe UDAPSecurity::SignedMetadataTrustVerificationTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_signed_metadata_trust_verification') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }

  let(:client_cert) do
    raw_cert = File.read(File.join(File.dirname(__FILE__),
                                   '../fixtures/EMRDirectTestServerCert.pem'))
    OpenSSL::X509::Certificate.new raw_cert
  end

  let(:intermediate_ca) do
    raw_cert = File.read(File.join(File.dirname(__FILE__),
                                   '../fixtures/EMRDirectTestIntermediateCA.pem'))
    OpenSSL::X509::Certificate.new raw_cert
  end

  let(:root_ca) do
    raw_cert = File.read(File.join(File.dirname(__FILE__),
                                   '../fixtures/EMRDirectTestRootCA.pem'))
    OpenSSL::X509::Certificate.new raw_cert
  end

  let(:invalid_trust_anchor) do
    UDAPSecurity::DefaultCertFileLoader.load_default_ca_pem_file
  end

  let(:signing_algorithm) { 'RS256' }

  # Occurs when full cert chain provided in x5c header but chain's root CA not
  # set as a trust anchor
  # Algorithm encounters a self-signed cert (the root CA), ending the chain,
  # but no certs have matched a trusted source yet
  let(:self_signed_cert_error) { 'self-signed certificate in certificate chain' }

  # Occurs when the issuing cert of a cert in the chain being verified is not
  # on hand
  # E.g., client cert is in chain but system does not have access to
  # intermediate CA
  # Or, intermediate CA is in chain but system does not have access to root CA
  let(:missing_cert_error) { 'unable to get local issuer certificate' }

  # Occurs when intermediate CA is set as trust anchor but not root CA
  # Since intermediate CA is not self-signed, it cannot be true trust anchor and
  # algorithm must verify its issuer (the root CA) but it does not have access
  # to root CA
  let(:missing_trust_anchor_error) { 'unable to get issuer certificate' }

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

  def create_test_jwt(include_intermediate_ca: true, include_root_ca: true)
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    x5c_certs = [client_cert.to_pem]
    x5c_certs.append(intermediate_ca.to_pem) if include_intermediate_ca
    x5c_certs.append(root_ca.to_pem) if include_root_ca
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

  context 'when JWT includes client, intermediate, and root certs' do
    it 'passes when only root CA provided as trust anchor' do
      WebMock.allow_net_connect!

      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: root_ca.to_pem)
      expect(result.result).to eq('pass')
    end

    it 'passes when both intermediate and root CAs provided as trust anchor' do
      WebMock.allow_net_connect!

      trust_anchors = "#{root_ca.to_pem},#{intermediate_ca.to_pem}"
      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: trust_anchors)
      expect(result.result).to eq('pass')
    end

    it 'fails when intermediate CA but not root CA is provided as trust anchor' do
      WebMock.allow_net_connect!

      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: intermediate_ca.to_pem)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(missing_trust_anchor_error)
    end

    it 'fails when incorrect root CA is provided as trust anchor' do
      WebMock.allow_net_connect!

      result = run(runnable, signed_metadata_jwt: create_test_jwt,
                             udap_server_trust_anchor_certs: invalid_trust_anchor)
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(self_signed_cert_error)
    end
  end

  context 'when JWT includes client and intermediate certs' do
    it 'passes when only root CA provided as trust anchor' do
      WebMock.allow_net_connect!

      result = run(runnable,
                   signed_metadata_jwt: create_test_jwt(include_root_ca: false),
                   udap_server_trust_anchor_certs: root_ca.to_pem)
      expect(result.result).to eq('pass')
    end

    it 'passes when both intermediate and root CAs provided as trust anchor' do
      WebMock.allow_net_connect!

      trust_anchors = "#{root_ca.to_pem},#{intermediate_ca.to_pem}"
      result = run(runnable,
                   signed_metadata_jwt: create_test_jwt(include_root_ca: false),
                   udap_server_trust_anchor_certs: trust_anchors)
      expect(result.result).to eq('pass')
    end

    it 'fails when intermediate CA but not root CA is provided as trust anchor' do
      WebMock.allow_net_connect!

      result = run(runnable,
                   signed_metadata_jwt: create_test_jwt(include_root_ca: false),
                   udap_server_trust_anchor_certs: intermediate_ca.to_pem)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(missing_trust_anchor_error)
    end

    it 'fails when incorrect root CA is provided as trust anchor' do
      WebMock.allow_net_connect!

      result = run(runnable,
                   signed_metadata_jwt: create_test_jwt(include_root_ca: false),
                   udap_server_trust_anchor_certs: invalid_trust_anchor)
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(missing_cert_error)
    end
  end

  context 'when JWT includes only client cert' do
    it 'fails when only root CA but not intermediate CA provided as trust anchor' do
      WebMock.allow_net_connect!

      result = run(runnable,
                   signed_metadata_jwt: create_test_jwt(include_root_ca: false, include_intermediate_ca: false),
                   udap_server_trust_anchor_certs: root_ca.to_pem)
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(missing_cert_error)
    end

    it 'passes when both intermediate and root CAs provided as trust anchors' do
      WebMock.allow_net_connect!

      trust_anchors = "#{root_ca.to_pem},#{intermediate_ca.to_pem}"
      result = run(runnable,
                   signed_metadata_jwt: create_test_jwt(include_root_ca: false, include_intermediate_ca: false),
                   udap_server_trust_anchor_certs: trust_anchors)
      expect(result.result).to eq('pass')
    end

    it 'fails when intermediate CA but not root CA is provided as trust anchor' do
      WebMock.allow_net_connect!

      result = run(runnable,
                   signed_metadata_jwt: create_test_jwt(include_root_ca: false, include_intermediate_ca: false),
                   udap_server_trust_anchor_certs: intermediate_ca.to_pem)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(missing_trust_anchor_error)
    end

    it 'fails when incorrect root CA is provided as trust anchor' do
      WebMock.allow_net_connect!

      result = run(runnable,
                   signed_metadata_jwt: create_test_jwt(include_root_ca: false, include_intermediate_ca: false),
                   udap_server_trust_anchor_certs: invalid_trust_anchor)
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(missing_cert_error)
    end
  end
end
