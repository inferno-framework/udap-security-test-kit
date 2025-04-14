# frozen_string_literal: true

require 'rack/utils'

module UDAPSecurityTestKit
  RE_RUN_REGISTRATION_SUFFIX =
    'Create a new session and re-run the Client Registration group if you need to change this value.'
  INPUT_CLIENT_ID_DESCRIPTION_LOCKED =
    "The registered Client Id for use in obtaining access tokens. #{RE_RUN_REGISTRATION_SUFFIX}".freeze
  INPUT_UDAP_REGISTRATION_JWT_DESCRIPTION_LOCKED =
    "The software statement JWT provided during UDAP client registration. #{RE_RUN_REGISTRATION_SUFFIX}".freeze

  INPUT_LAUNCH_CONTEXT_DESCRIPTION =
    'Launch context details to be included in access token responses, specified as a JSON array. If provided, ' \
    'the contents will be merged into Inferno\'s token responses.'
  INPUT_FHIR_USER_RELATIVE_REFERENCE =
    'A FHIR relative reference (<resource type>/<id>) for the FHIR user record to return when the openid ' \
    'and fhirUser scopes are requested. Include this resource in the **Available Resources** input so ' \
    'that it can be accessed via FHIR read.'
  INPUT_FHIR_READ_RESOURCES_BUNDLE_DESCRIPTION =
    'Resources to make available in Inferno\'s simulated FHIR server provided as a FHIR bundle. Each entry ' \
    'must contain a resource with the id element populated. Each instance present will be available for ' \
    'retrieval from Inferno at the endpoint: <fhir-base>/<resource type>/<instance id>. These will only ' \
    'be available through the read interaction.'
  INPUT_ECHOED_FHIR_RESPONSE_DESCRIPTION =
    'JSON representation of a default FHIR resource for Inferno to echo when a request is made to the ' \
    'simulated FHIR server. Reads targetting resources in the **Available Resources** input will return ' \
    'that resource instead of this. Otherwise, the content here will be echoed back exactly and no check ' \
    'will be made that it is appropriate for the request made. If nothing is provided, an OperationOutcome ' \
    'indicating nothing to echo will be returned.'

  module ClientWaitDialogDescriptions
    def wait_dialog_client_credentials_access_prefix(client_id, fhir_base_url)
      <<~PREFIX
        **Access**

        Use the registered client id (#{client_id}) to obtain an access
        token using the [UDAP B2B client credentials flow](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)
        and use that token to access a FHIR endpoint under the simulated server's base URL

        `#{fhir_base_url}`
      PREFIX
    end

    def wait_dialog_authorization_code_access_prefix(client_id, fhir_base_url)
      <<~PREFIX
        **Access**

        Use the registered client id (#{client_id}) to obtain an access
        token using the UDAP [consumer-facing](https://hl7.org/fhir/us/udap-security/STU1/consumer.html)
        or [B2B authorization code flow](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)
        and use that token to access a FHIR endpoint under the simulated server's base URL

        `#{fhir_base_url}`
      PREFIX
    end

    def wait_dialog_access_response_and_continue_suffix(client_id, resume_pass_url)
      <<~SUFFIX
        Inferno will respond to requests with either:
        - A resource from the Bundle in the **Available Resources** input if the request is a read matching
          a resource type and id found in the Bundle.
        - Otherwise, the contents of the **Default FHIR Response** if provided.
        - Otherwise, an OperationOutcome indicating nothing to echo.

        [Click here](#{resume_pass_url}?token=#{client_id}) once you performed the data access.
      SUFFIX
    end
  end
end
