module UDAPSecurity
  class DefaultCertFileLoader
    def self.load_default_ca_pem_file
      raw_cert = File.read(File.join(File.dirname(__FILE__), '../../spec/fixtures/InfernoCA.pem'))
      cert = OpenSSL::X509::Certificate.new raw_cert
      cert.to_pem
    end

    def self.load_default_ca_private_key_file
      raw_key = File.read(File.join(File.dirname(__FILE__), '../../spec/fixtures/InfernoCA.key'))
      private_key = OpenSSL::PKey::RSA.new raw_key
      private_key.to_pem
    end

    def self.load_test_client_cert_pem_file
      raw_cert = File.read(File.join(File.dirname(__FILE__), '../../spec/fixtures/TestClient.pem'))
      cert = OpenSSL::X509::Certificate.new raw_cert
      cert.to_pem
    end

    def self.load_test_client_private_key_file
      raw_key = File.read(File.join(File.dirname(__FILE__), '../../spec/fixtures/TestClientPrivateKey.key'))
      key = OpenSSL::PKey::RSA.new raw_key
      key.to_pem
    end
  end
end
