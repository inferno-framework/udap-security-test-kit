require_relative 'registration_failure_invalid_contents_test'
require_relative 'registration_failure_invalid_jwt_signature_test'
require_relative 'registration_success_test'
require_relative 'registration_success_contents_test'

module UDAPSecurityTestKit
  class DynamicClientRegistrationGroup < Inferno::TestGroup
    title 'UDAP Dynamic Client Registration'
    description %(
     Generate and sign a software statement to register the client with the authorization server as described in the
     [dynamic client registration requirements](https://hl7.org/fhir/us/udap-security/STU1/registration.html).
    )
    id :udap_dynamic_client_registration_group

    def self.dynamic_client_registration_input_instructions
      %(
      Testers must provide a client certificate and any additional CAs needed for the authorization server under test to
      establish a trust chain.

      Cancelling a UDAP client's registration is not a required server capability and as such the Inferno client has no
      way of resetting state on the authorization server after a successful registration attempt.  If a given
      certificate and issuer URI identity combination has already been registered with the authorization server, testers
      whose systems support registration modifications
      may select the "Update Registration" option under Client Registration Status. This option will accept either a
      `200 OK` or `201 Created` return status. Registration attempts for a new client may only return `201 Created`,
      per the [IG](https://hl7.org/fhir/us/udap-security/STU1/registration.html#request-body).
    )
    end

    input_instructions dynamic_client_registration_input_instructions

    input :udap_registration_endpoint,
          title: 'UDAP Dynamic Client Registration Endpoint',
          description: %(
            The absolute URL of the dynamic client registration endpoint.
          )

    input :udap_registration_grant_type,
          title: 'Client Registration Grant Type',
          description: %(
            The OAuth2.0 grant type for which this client will register itself. A given client may register as either
             option, but not both.
          ),
          type: 'radio',
          options: {
            list_options: [
              {
                label: 'Authorization Code',
                value: 'authorization_code'
              },
              {
                label: 'Client Credentials',
                value: 'client_credentials'
              }
            ]
          }

    input :udap_client_registration_status,
          title: 'Client Registration Status',
          description: %(
            If the client's iss and certificate combination has already been registered with the authorization server
            prior to this test run, select 'Update'.
          ),
          type: 'radio',
          options: {
            list_options: [
              {
                label: 'New Registration (201 Response Code Expected)',
                value: 'new'
              },
              {
                label: 'Update Registration (200 or 201 Response Code Expected)',
                value: 'update'
              }
            ]
          },
          default: 'new'

    input :udap_client_cert_pem,
          title: 'X.509 Client Certificate(s) (PEM Format)',
          description: %(
            A list of one or more X.509 certificates in PEM format separated by a newline. The first (leaf) certificate
            MUST represent the client entity Inferno will register as,
            and the trust chain that will be built from the provided certificate(s) must resolve to a CA trusted by the
            authorization server under test.
          ),
          type: 'textarea',
          optional: false

    input :udap_client_private_key_pem,
          title: 'Client Private Key (PEM Format)',
          description: %(
          The private key corresponding to the client certificate used for registration, in PEM format.  Used to sign
          registration and/or authentication JWTs.
          ),
          type: 'textarea',
          optional: false

    input :udap_cert_iss,
          title: 'JWT Issuer (iss) Claim',
          description: %(
            MUST correspond to a unique URI entry in the Subject Alternative Name (SAN) extension of the client
            certificate used for registration.
          ),
          optional: false

    input :udap_jwt_signing_alg,
          title: 'JWT Signing Algorithm',
          description: %(
            Algorithm used to sign UDAP JSON Web Tokens (JWTs). UDAP Implementations SHALL support
            RS256.
            ),
          type: 'radio',
          options: {
            list_options: [
              {
                label: 'RS256',
                value: 'RS256'
              }
            ]
          },
          default: 'RS256',
          locked: true

    input :udap_registration_requested_scope,
          title: 'Scope(s) Requested',
          description: %(
            String containing a space delimited list of scopes requested by the client application for use in
             subsequent requests. The Authorization Server MAY consider this list when deciding the scopes that it will
            allow the application to subsequently request. Apps requesting the "client_credentials" grant type SHOULD
            request system scopes; apps requesting
            the "authorization_code" grant type SHOULD request user or patient scopes.
          )

    input :udap_registration_certifications,
          title: 'UDAP Certifications',
          description: %(
            Additional UDAP certifications to include in registration request, if required by the authorization server.
             Include a space separated list of strings representing a Base64-encoded, signed JWT.
            ),
          type: 'textarea',
          optional: true

    test from: :udap_registration_failure_invalid_contents
    test from: :udap_registration_failure_invalid_jwt_signature
    test from: :udap_registration_success
    test from: :udap_registration_success_contents
  end
end
