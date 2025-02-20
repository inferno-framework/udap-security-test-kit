require_relative 'version'

module UDAPSecurityTestKit
  class Metadata < Inferno::TestKit
    id :udap_security
    title 'UDAP Security'
    description <<~DESCRIPTION
      This is a collection of tests to verify server conformance to the [HL7 UDAP Security
      STU 1.0 IG](https://hl7.org/fhir/us/udap-security/STU1/index.html)
      <!-- break -->
      Specifically, this test
      kit assesses the required capabilities from the following sections:
      - [JSON Web Token (JWT) Requirements](https://hl7.org/fhir/us/udap-security/STU1/index.html)
      - [Discovery](https://hl7.org/fhir/us/udap-security/STU1/discovery.html)
      - [Dynamic Client Registration](https://hl7.org/fhir/us/udap-security/STU1/registration.html)
      - [Consumer-Facing Authorization & Authentication](https://hl7.org/fhir/us/udap-security/STU1/consumer.html)
      - [Business-to-Business (B2B) Authorization & Authentication](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)

      [Tiered OAuth for User
      Authentication](https://hl7.org/fhir/us/udap-security/STU1/user.html) is not a
      required capability and is not assessed.
      This test kit also does not assess client conformance.
    DESCRIPTION
    suite_ids [:udap_security]
    tags ['UDAP Security']
    last_updated '2025-01-09'
    version VERSION
    maturity 'Low'
    authors 'inferno@groups.mitre.org'
    repo 'https://github.com/inferno-framework/udap-security-test-kit'
  end
end
