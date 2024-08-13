require_relative '../../lib/udap_security_test_kit/udap_jwt_validator'
require_relative '../../lib/udap_security_test_kit/udap_jwt_builder'
require_relative '../../lib/udap_security_test_kit/udap_x509_certificate'
require_relative '../../lib/udap_security_test_kit/default_cert_file_loader'
require 'pry'

RSpec.describe UDAPSecurityTestKit::UDAPJWTValidator do # rubocop:disable RSpec/FilePath,RSpec/SpecFilePathFormat
  let(:inferno_client_cert) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:inferno_client_private_key) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_private_key_file
  end

  let(:inferno_root_ca) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_default_ca_pem_file
  end

  let(:signing_algorithm) { 'RS256' }

  let(:mock_crl_endpoint) { 'https://inferno.com/mock_crl_endpoint.crl' }

  let(:inferno_crl) do
    File.read(File.join(File.dirname(__FILE__), '../../spec/fixtures/crl/InfernoCA_CRL.pem'))
  end

  describe 'validate_trust_chain' do
    it 'returns that trust chain is valid with correct inputs' do
      stub_request(:get, mock_crl_endpoint)
        .to_return(status: 200, body: inferno_crl)

      test_jwt = UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
        {},
        inferno_client_private_key,
        signing_algorithm,
        [inferno_client_cert, inferno_root_ca]
      )

      _token_body, token_header = JWT.decode(test_jwt, nil, false)
      trust_anchor_certs = [OpenSSL::X509::Certificate.new(inferno_root_ca)]

      validation_result = described_class.validate_trust_chain(
        token_header['x5c'],
        trust_anchor_certs
      )
      expect(validation_result[:success]).to be true
      unless validation_result[:success]
        puts "Trust chain validation error message: #{validation_result[:error_message]}"
      end
    end

    it 'returns that trust chain cannot be verified if CRL endpoint not accessible' do
      stub_request(:get, mock_crl_endpoint)
        .to_return(status: 503, body: {}.to_json)

      test_jwt = UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
        {},
        inferno_client_private_key,
        signing_algorithm,
        [inferno_client_cert, inferno_root_ca]
      )

      _token_body, token_header = JWT.decode(test_jwt, nil, false)
      trust_anchor_certs = [OpenSSL::X509::Certificate.new(inferno_root_ca)]

      validation_result = described_class.validate_trust_chain(
        token_header['x5c'],
        trust_anchor_certs
      )
      expect(validation_result[:success]).to be false
      expect(validation_result[:error_message]).to match(/PEM_read_bio_X509_CRL: no start line/)
    end
  end

  describe 'validate_signature' do
    it 'returns that signature is valid with correct inputs' do
      test_jwt = UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
        {},
        inferno_client_private_key,
        signing_algorithm,
        [inferno_client_cert]
      )
      _token_body, token_header = JWT.decode(test_jwt, nil, false)

      cert = OpenSSL::X509::Certificate.new(Base64.urlsafe_decode64(token_header['x5c'].first))

      validation_result = described_class.validate_signature(
        test_jwt,
        token_header['alg'],
        cert
      )

      expect(validation_result[:success]).to be true
      unless validation_result[:success]
        puts "JWT Signature validation error message: #{validation_result[:error_message]}"
      end
    end
  end
end
