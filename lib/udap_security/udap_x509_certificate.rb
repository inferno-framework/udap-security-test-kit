module UDAPSecurity
  class UDAPX509Certificate
    attr_reader :san, :cert_private_key, :cert

    def initialize(issuer_cert_pem_string, issuer_private_key_pem_string)
      issuer_private_key = OpenSSL::PKey.read(issuer_private_key_pem_string)
      issuer_cert = OpenSSL::X509::Certificate.new(issuer_cert_pem_string)

      @cert_private_key = OpenSSL::PKey::RSA.new 2048
      cert = OpenSSL::X509::Certificate.new

      # must be v3 or above to allow extensions
      # x509 versions are zero-based, so '2' means version 3
      cert.version = 2

      # X.509 serial numbers can be up to 20 bytes (2**(8*20))
      cert.serial = SecureRandom.random_number(2**32)
      cert.subject = OpenSSL::X509::Name.parse '/C=US/ST=MA/L=Bedford/O=Inferno/CN=UDAP-Test-Client'
      cert.issuer = issuer_cert.subject
      cert.public_key = cert_private_key.public_key
      cert.not_before = Time.now
      cert.not_after = cert.not_before + (1 * 365 * 24 * 60 * 60) # 1 years validity
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = issuer_cert

      # SAN must be unique for each cert
      @san = "https://inferno.org/udap_security/#{cert.serial}"
      unique_uri_entry = "URI:#{@san}"

      # TODO: add in any other relevant extensions?
      cert.add_extension(ef.create_extension('keyUsage', 'digitalSignature, nonRepudiation', true))
      cert.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash', false))
      cert.add_extension(ef.create_extension('subjectAltName', unique_uri_entry, false))
      cert.sign(issuer_private_key, OpenSSL::Digest.new('SHA256'))

      @cert = cert
    end
  end
end
