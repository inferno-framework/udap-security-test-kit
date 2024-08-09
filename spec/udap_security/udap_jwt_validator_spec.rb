require_relative '../../lib/udap_security/udap_jwt_validator'
require_relative '../../lib/udap_security/udap_jwt_builder'
require_relative '../../lib/udap_security/udap_x509_certificate'
require_relative '../../lib/udap_security/default_cert_file_loader'
require 'pry'

RSpec.describe UDAPSecurity::UDAPJWTValidator do # rubocop:disable RSpec/FilePath,RSpec/SpecFilePathFormat
  # Two sets of test certs - EMR certs for trust chain validation, since they
  # have a legitimate trust chain
  # Inferno self-generated certs for JWT signature validation, since we have
  # access to private key and can generate signed JWTs as a result
  let(:emr_client_cert) do
    raw_cert = File.read(File.join(File.dirname(__FILE__),
                                   '../fixtures/EMRDirectTestServerCert.pem'))
    OpenSSL::X509::Certificate.new raw_cert
  end

  let(:emr_intermediate_ca) do
    raw_cert = File.read(File.join(File.dirname(__FILE__),
                                   '../fixtures/EMRDirectTestIntermediateCA.pem'))
    OpenSSL::X509::Certificate.new raw_cert
  end

  let(:emr_root_ca) do
    raw_cert = File.read(File.join(File.dirname(__FILE__),
                                   '../fixtures/EMRDirectTestRootCA.pem'))
    OpenSSL::X509::Certificate.new raw_cert
  end

  let(:inferno_client_cert) do
    UDAPSecurity::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:inferno_client_private_key) do
    UDAPSecurity::DefaultCertFileLoader.load_test_client_private_key_file
  end

  let(:inferno_root_ca) do
    UDAPSecurity::DefaultCertFileLoader.load_default_ca_pem_file
  end

  let(:signing_algorithm) { 'RS256' }

  describe 'validate_trust_chain' do
    it 'returns that trust chain is valid with correct inputs' do
      WebMock.allow_net_connect!
      # Since input certs are real, using dummy private key to generate JWT
      # Since we do not have access to real certs and its private key
      # Won't matter because JWT signature not validated as part of this particular method
      rsa_private = OpenSSL::PKey::RSA.generate 2048
      test_jwt = UDAPSecurity::UDAPJWTBuilder.encode_jwt_with_x5c_header(
        {},
        rsa_private.to_pem,
        signing_algorithm,
        [emr_client_cert.to_pem, emr_intermediate_ca.to_pem]
      )

      _token_body, token_header = JWT.decode(test_jwt, nil, false)
      trust_anchor_certs = [emr_root_ca]

      validation_result = described_class.validate_trust_chain(
        token_header['x5c'],
        trust_anchor_certs
      )
      expect(validation_result[:success]).to be true
      unless validation_result[:success]
        puts "Trust chain validation error message: #{validation_result[:error_message]}"
      end
    end

    it 'returns that trust chain cannot be verified with invalid certs' do
      WebMock.allow_net_connect!
      test_jwt = UDAPSecurity::UDAPJWTBuilder.encode_jwt_with_x5c_header(
        {},
        inferno_client_private_key,
        signing_algorithm,
        [inferno_client_cert]
      )

      _token_body, token_header = JWT.decode(test_jwt, nil, false)

      trust_anchor_certs = [OpenSSL::X509::Certificate.new(inferno_root_ca)]

      validation_result = described_class.validate_trust_chain(
        token_header['x5c'],
        trust_anchor_certs
      )

      expect(validation_result[:success]).to be false
      expect(validation_result[:error_message]).to match(/unable to get certificate CRL/)
    end
  end

  describe 'validate_signature' do
    it 'returns that signature is valid with correct inputs' do
      test_jwt = UDAPSecurity::UDAPJWTBuilder.encode_jwt_with_x5c_header(
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
