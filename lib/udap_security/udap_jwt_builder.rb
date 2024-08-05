require 'jwt'
require 'base64'

module UDAPSecurity
  class UDAPJWTBuilder
    def self.generate_private_key(pkey_string)
      OpenSSL::PKey.read(pkey_string)
    end

    def self.parse_cert_strings_from_user_input(user_input_string)
      x5c_certs = user_input_string.split(',')
      x5c_certs.each_with_index do |cert, index|
        cleaned_input = cert.chomp.strip
        x5c_certs[index] = cleaned_input
      end
    end

    def self.encode_jwt_no_x5c_header(payload, private_key, alg)
      JWT.encode payload, private_key, alg
    end

    def self.encode_jwt_with_x5c_header(payload, private_key_pem_string, alg, x5c_certs_pem_string)
      private_key = OpenSSL::PKey.read(private_key_pem_string)

      x5c_certs_encoded = x5c_certs_pem_string.map do |cert|
        cert_pem = OpenSSL::X509::Certificate.new(cert)
        Base64.urlsafe_encode64(cert_pem.to_der)
      end

      JWT.encode payload, private_key, alg, { x5c: x5c_certs_encoded }
    end
  end
end
