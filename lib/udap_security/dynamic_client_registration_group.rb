require_relative 'generate_client_certs_test'
require_relative 'registration_failure_invalid_contents_test'
require_relative 'registration_failure_invalid_jwt_signature_test'
require_relative 'registration_success_test'
require_relative 'registration_success_contents_test'

module UDAPSecurity
  class DynamicClientRegistrationGroup < Inferno::TestGroup
    title 'UDAP Dynamic Client Registration'
    description %(
     Generate and sign a software statement to register the client with the authorization server.  Auto-generates a new
     client certificate for each run of the test group if custom certs are not provided.
    )
    id :udap_dynamic_client_registration_group

    input_instructions %(
      If using auto-generated client certificates, Inferno's default self-signed certificate authority will issue and
      sign the client cert(s). The default Inferno CA can be downloaded as a PEM file at the following link:
      * `#{Inferno::Application[:base_url]}/custom/udap_security/inferno_ca.pem`

      Alternatively, testers may input their own client certificates signed by their own CA. Either way, **the
      authorization server under test MUST be configured to trust the signing certificate** before Dynamic Client
      Registration tests are run.

      Each run of the dynamic client registration tests requires unique
      a unique client cert and private key. To auto-generate a fresh set,
      clear the those inputs prior to re-running.
    )

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

    test from: :udap_generate_client_certs
    test from: :udap_registration_failure_invalid_contents
    test from: :udap_registration_failure_invalid_jwt_signature
    test from: :udap_registration_success
    test from: :udap_registration_success_contents
  end
end
