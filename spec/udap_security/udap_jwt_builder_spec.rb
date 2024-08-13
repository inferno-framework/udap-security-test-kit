require_relative '../../lib/udap_security/udap_jwt_builder'
require_relative '../../lib/udap_security/default_cert_file_loader'

RSpec.describe UDAPSecurityTestKit::UDAPJWTBuilder do # rubocop:disable RSpec/FilePath,RSpec/SpecFilePathFormat
  let(:jwt_alg) { 'RS256' }
  let(:rsa_private_string) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_private_key_file
  end

  let(:client_cert_string) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:ca_cert_string) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_default_ca_pem_file
  end

  def validate_cert_array(contents, expected_length)
    expect(contents.length).to eq(expected_length)
    contents.each do |cert|
      # verify we can create a valid certificate object from contents
      OpenSSL::X509::Certificate.new(cert)
    end
  end

  describe 'encode_jwt_no_x5c_header' do
    it 'creates a signed, valid JWT without x5c headers using a random generated key' do
      rsa_private = OpenSSL::PKey::RSA.generate 2048
      rsa_public = rsa_private.public_key

      private_key = described_class.generate_private_key(rsa_private.to_s)

      payload = { 'test_key' => 'test_value' }

      encoded_jwt = described_class.encode_jwt_no_x5c_header(payload, private_key, jwt_alg)

      # verify we can decode it correctly
      jwt_body, jwt_header = JWT.decode encoded_jwt, rsa_public, true, { algorithm: jwt_alg }

      expect(jwt_body).to eq(payload)
      expect(jwt_header.size).to eq 1
      expect(jwt_header['alg']).to eq(jwt_alg)
    end

    it 'creates a signed, valid JWT without x5c headers using PEM-formatted string' do
      rsa_private = described_class.generate_private_key(rsa_private_string)
      rsa_public = rsa_private.public_key

      payload = { 'test_key' => 'test_value' }

      encoded_jwt = described_class.encode_jwt_no_x5c_header(payload, rsa_private, jwt_alg)

      jwt_body, jwt_header = JWT.decode encoded_jwt, rsa_public, true, { algorithm: jwt_alg }

      expect(jwt_body).to eq(payload)
      expect(jwt_header.size).to eq 1
      expect(jwt_header['alg']).to eq(jwt_alg)
    end
  end

  describe 'encode_jwt_with_x5c_header' do
    it 'creates a signed, valid JWT with x5c headers using PEM-formatted strings' do
      payload = { 'test_key' => 'test_value' }

      encoded_jwt = described_class.encode_jwt_with_x5c_header(payload, rsa_private_string, jwt_alg,
                                                               [client_cert_string])

      rsa_private = described_class.generate_private_key(rsa_private_string)
      rsa_private.public_key

      # verify JWT contents
      jwt_body, jwt_header = JWT.decode(encoded_jwt, nil, false)

      expect(jwt_body).to eq(payload)
      expect(jwt_header).to include('x5c')
      expect(jwt_header).to include('alg')
      expect(jwt_header['alg']).to eq(jwt_alg)
      expect(jwt_header['x5c'].is_a?(Array)).to be true

      # verify enclosed certificate
      cert = OpenSSL::X509::Certificate.new(Base64.urlsafe_decode64(jwt_header['x5c'].first))

      jwt_client_cert = OpenSSL::X509::Certificate.new(Base64.urlsafe_decode64(jwt_header['x5c'].first))
      expect(jwt_client_cert.check_private_key(rsa_private)).to be true

      ca_cert = OpenSSL::X509::Certificate.new(ca_cert_string)
      ca_public_key = ca_cert.public_key

      expect(jwt_client_cert.verify(ca_public_key)).to be true

      # verify signature
      JWT.decode(
        encoded_jwt,
        cert.public_key,
        true,
        algorithm: jwt_header['alg']
      )
    end

    it 'creates an invalid JWT when signing key does not correspond to x5c certificate' do
      rsa_private = OpenSSL::PKey::RSA.generate 2048
      payload = { 'test_key' => 'test_value' }

      encoded_jwt = described_class.encode_jwt_with_x5c_header(payload, rsa_private.to_s, jwt_alg, [client_cert_string])

      # works with correct public key
      jwt_body, jwt_header = JWT.decode encoded_jwt, rsa_private.public_key, true, { algorithm: jwt_alg }

      expect(jwt_body).to eq(payload)
      expect(jwt_header).to include('x5c')
      expect(jwt_header).to include('alg')
      expect(jwt_header['alg']).to eq(jwt_alg)
      expect(jwt_header['x5c'].is_a?(Array)).to be true

      # fails when using public key from attached certificate
      jwt_client_cert = OpenSSL::X509::Certificate.new(Base64.urlsafe_decode64(jwt_header['x5c'].first))

      expect do
        JWT.decode encoded_jwt, jwt_client_cert.public_key, true, { algorithm: jwt_alg }
      end.to raise_error(JWT::VerificationError)
    end
  end

  describe 'split_user_input_cert_string' do
    it 'correctly splits single certificate' do
      cert_array = described_class.split_user_input_cert_string(client_cert_string)

      expect(cert_array.length).to eq(1)
      OpenSSL::X509::Certificate.new(cert_array[0])
    end

    it 'correctly splits multiple certificates' do
      cert_input = "#{client_cert_string}\n#{ca_cert_string}"
      cert_array = described_class.split_user_input_cert_string(cert_input)

      expect(cert_array.length).to eq(2)
      cert_array.each do |cert|
        # verify we can create a valid certificate object from contents
        OpenSSL::X509::Certificate.new(cert)
      end
    end
  end
end
