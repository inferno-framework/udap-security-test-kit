module UDAPSecurityTestKit
  class DefaultCertFileLoader
    def self.load_default_ca_pem_file
      raw_cert = File.read(File.join(File.dirname(__FILE__), 'certs/InfernoCA.pem'))
      cert = OpenSSL::X509::Certificate.new raw_cert
      cert.to_pem
    end

    def self.load_default_ca_private_key_file
      raw_key = File.read(File.join(File.dirname(__FILE__), 'certs/InfernoCA.key'))
      private_key = OpenSSL::PKey::RSA.new raw_key
      private_key.to_pem
    end

    def self.load_test_client_cert_pem_file
      raw_cert = File.read(File.join(File.dirname(__FILE__), 'certs/TestClient.pem'))
      cert = OpenSSL::X509::Certificate.new raw_cert
      cert.to_pem
    end

    def self.load_test_client_private_key_file
      raw_key = File.read(File.join(File.dirname(__FILE__), 'certs/TestClientPrivateKey.key'))
      key = OpenSSL::PKey::RSA.new raw_key
      key.to_pem
    end

    def self.load_specified_private_key(key_name)
      if key_name == 'SureFhir'
        raw_key = File.read(ENV.fetch('SURE_FHIR_PKEY_FILE_PATH'))
        key = OpenSSL::PKey::RSA.new raw_key
      elsif key_name == 'EMRDirect'
        raw_key = File.read(ENV.fetch('EMR_DIRECT_ENCRYPTED_PKEY_FILE_PATH'))
        passphrase = ENV.fetch('EMR_DIRECT_PKEY_PASSPHRASE')
        key = OpenSSL::PKey::RSA.new(raw_key, passphrase)
      end
      key
    end

    def self.load_specified_client_cert(cert_name)
      if cert_name == 'SureFhir'
        # TODO: change to env variables
        raw_cert = File.read('/Users/awallace/Desktop/test_certs/jan-2025-connectathon/surefhir-certs/custom-client-certs/SureFhirClientCert.pem')
        cert = OpenSSL::X509::Certificate.new raw_cert
      elsif cert_name == 'EMRDirect'
        raw_cert = File.read('/Users/awallace/Desktop/test_certs/jan-2025-connectathon/phimail-credentials/emr-direct-certs/EMRDirectClientCert.pem')
        cert = OpenSSL::X509::Certificate.new raw_cert
      end
      cert
    end
  end
end
