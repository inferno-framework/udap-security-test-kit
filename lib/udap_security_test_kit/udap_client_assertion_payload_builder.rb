module UDAPSecurityTestKit
  class UDAPClientAssertionPayloadBuilder
    def self.build(iss, aud, extensions)
      {
        iss:,
        sub: iss,
        aud:,
        exp: 5.minutes.from_now.to_i,
        iat: Time.now.to_i,
        jti: SecureRandom.hex(32),
        extensions:
      }.compact
    end
  end
end
