require 'jwt'

module UDAPSecurityTestKit
  class UDAPJWTValidator
    def self.validate_signature(signed_metadata_jwt, algorithm, cert)
      JWT.decode(
        signed_metadata_jwt,
        cert.public_key,
        true,
        algorithm:
      )
      {
        success: true,
        error_message: nil
      }
    rescue JWT::DecodeError => e
      {
        success: false,
        error_message: e.full_message
      }
    end

    def self.validate_trust_chain(x5c_header_encoded, trust_anchor_certs)
      cert_chain = x5c_header_encoded.map do |cert|
        cert_der = Base64.urlsafe_decode64(cert)
        OpenSSL::X509::Certificate.new(cert_der)
      end
      crl_uris = cert_chain.map(&:crl_uris).compact.flatten
      crl_uris_anchors = trust_anchor_certs.map(&:crl_uris).compact.flatten
      crl_uris.concat(crl_uris_anchors)
      begin
        crls = crl_uris.map do |uri|
          get_crl_from_uri(uri)
        end
      rescue OpenSSL::X509::CRLError => e
        return {
          success: false,
          error_message: e.message
        }
      end

      begin
        # JWT library can validate the trust chain while decoding the provided
        # JWT/verifying its signature, but we don't have currently have access
        # to certs that satisfy both prerequisites to doing this. We have:
        # A) client certs that can establish a legitimate trust chain (but don't
        # have access to private key needed to create a valid, signed JWT with them)
        # B) client certs that have a valid private key (but which cannot
        # establish a legitimate trust chain)
        # As a result, these capabilities are decoupled for testing purposes
        JWT::X5cKeyFinder.new(trust_anchor_certs,
                              crls).from(x5c_header_encoded)
        {
          success: true,
          error_message: nil
        }
      rescue JWT::VerificationError => e
        {
          success: false,
          error_message: e.full_message
        }
      end
    end

    def self.get_crl_from_uri(crl_uri)
      uri = URI(crl_uri)
      crl = Net::HTTP.get(uri)
      OpenSSL::X509::CRL.new(crl)
    end
  end
end
