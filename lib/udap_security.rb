require_relative 'udap_security/authorization_code_group'
require_relative 'udap_security/client_credentials_group'

module UDAPSecurity
  class Suite < Inferno::TestSuite
    id :udap_security
    title 'UDAP Security'
    description %(
      The User Data Access Protocol (UDAP) Security test kit verifies that systems correctly implement the
      [UDAP Security IG](http://hl7.org/fhir/us/udap-security/STU1/)
      for extending OAuth 2.0 using UDAP workflows.

      There are three steps to the workflow:
      1. Discovery
      2. Dynamic Client Registration
      3. Authorization & Authentication

      These steps are grouped by the OAuth2.0 flow being tested:
      1. Authorization Code flow, which supports
        [Consumer-Facing](https://hl7.org/fhir/us/udap-security/STU1/consumer.html) or [Business-to-Business (B2B)](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)
        use cases
      2. Client Credentials flow, which only supports the
      [B2B](https://hl7.org/fhir/us/udap-security/STU1/b2b.html) use case

      Testers may test one or both flows based on their system under test.
    )

    input_instructions %(

    )

    cert_file = File.read(File.join(File.dirname(__FILE__), 'udap_security/certs/InfernoCA.pem'))
    cert_file_route_handler = proc { [200, { 'Content-Type' => 'application/x-pem-file' }, [cert_file]] }

    route(:get, '/inferno_ca.pem', cert_file_route_handler)

    resume_test_route :get, '/redirect' do |request|
      request.query_parameters['state']
    end

    group from: :udap_authorization_code_group
    group from: :udap_client_credentials_group
  end
end
