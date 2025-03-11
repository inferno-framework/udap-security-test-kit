require 'jwt'
require 'base64'

module UDAPSecurityTestKit
  class UDAPJWTBuilder
    def self.generate_private_key(pkey_string)
      OpenSSL::PKey.read(pkey_string)
    end

    def self.split_user_input_cert_string(user_input_string)
      regex = /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m
      user_input_string.scan(regex)
    end

    def self.encode_jwt_no_x5c_header(payload, private_key, alg)
      JWT.encode payload, private_key, alg
    end

    def self.encode_jwt_with_x5c_header(payload, private_key_pem_string, alg, x5c_certs_pem_string)
      private_key = OpenSSL::PKey.read(private_key_pem_string)

      x5c_certs_encoded = x5c_certs_pem_string.map do |cert|
        cert_pem = OpenSSL::X509::Certificate.new(cert)
        Base64.strict_encode64(cert_pem.to_der).chomp
      end

      JWT.encode payload, private_key, alg, { x5c: x5c_certs_encoded }
    end
  end
end
