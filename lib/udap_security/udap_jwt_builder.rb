require 'jwt'
require 'base64'

module UDAPSecurity
  class UDAPJWTBuilder
    def self.generate_private_key(pkey_string)
      OpenSSL::PKey.read(pkey_string)
    end

    def self.encode_jwt_no_x5c_header(payload, private_key, alg)
      JWT.encode payload, private_key, alg
    end

    def self.encode_jwt_with_x5c_header(payload, private_key_pem_string, alg, cert_pem_string)
      private_key = OpenSSL::PKey.read(private_key_pem_string)

      # TODO: handle certificate chains
      cert_pem = OpenSSL::X509::Certificate.new(cert_pem_string)

      cert_der_encoded = Base64.urlsafe_encode64(cert_pem.to_der)

      JWT.encode payload, private_key, alg, { x5c: [cert_der_encoded] }
    end
  end
end
