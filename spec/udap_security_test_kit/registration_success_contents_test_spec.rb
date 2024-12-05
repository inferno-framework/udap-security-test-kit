require_relative '../../lib/udap_security_test_kit/registration_success_contents_test'

RSpec.describe UDAPSecurityTestKit::RegistrationSuccessContentsTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_registration_success_contents') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }

  let(:udap_software_statement_json) do
    '{"iss":"https://inferno.org/udap_security_test_kit/1716937143",
    "sub":"https://inferno.org/udap_security_test_kit/1716937143",
    "aud":"http://example.fhir.org/registration",
    "exp":1716937449,
    "iat":1716937149,"jti":"1f625c375762e3e603299f1a522046c4fb20aeacab9d8d7ed9c54241ec68ea0f",
    "client_name":"Inferno UDAP Authorization Code Test Client",
    "redirect_uris":["https:/localhost/suites/custom/udap_security_test_kit/redirect"],
    "contacts":["mailto:inferno@groups.mitre.org"],
    "logo_uri":"https://inferno-framework.github.io/assets/inferno_logo.png",
    "grant_types":["authorization_code"],
    "response_types":["code"],
    "token_endpoint_auth_method":"private_key_jwt",
    "scope":"user/*.read"}'
  end

  let(:udap_software_statement_jwt) { 'example_jwt' }
  let(:udap_registration_grant_type) { 'authorization_code' }
  let(:correct_response) do
    '{"client_id": "example_client_id",
      "software_statement": "example_jwt",
      "client_name": "Inferno UDAP Authorization Code Test Client",
      "redirect_uris": ["https:/localhost/suites/custom/udap_security_test_kit/redirect"],
      "grant_types": ["authorization_code"],
      "response_types": ["code"],
      "token_endpoint_auth_method": "private_key_jwt",
      "scope": "user/*.read"}'
  end

  let(:required_immutable_claims) do
    ['grant_types',
     'token_endpoint_auth_method']
  end

  let(:required_mutable_claims) do
    ['scope', 'client_name']
  end

  let(:all_required_claims) do
    (required_immutable_claims + required_mutable_claims).append('client_id')
  end

  def run(runnable, inputs = {})
    test_run_params = { test_session_id: test_session.id }.merge(runnable.reference_hash)
    test_run = Inferno::Repositories::TestRuns.new.create(test_run_params)
    inputs.each do |name, value|
      session_data_repo.save(
        test_session_id: test_session.id,
        name:,
        value:,
        type: runnable.config.input_type(name)
      )
    end
    Inferno::TestRunner.new(test_session:, test_run:).run(runnable)
  end

  it 'fails if response does not include required claims' do
    all_required_claims.each do |key|
      response_json = JSON.parse(correct_response)
      response_json.delete(key)
      result = run(runnable,
                   udap_software_statement_json:,
                   udap_software_statement_jwt:,
                   udap_registration_response: JSON.generate(response_json),
                   udap_registration_grant_type:)
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(key.to_s)
    end
  end

  it 'fails if response values for required claims are blank' do
    all_required_claims.each do |key|
      response_json = JSON.parse(correct_response)
      response_json[key] = ''
      result = run(runnable,
                   udap_software_statement_json:,
                   udap_software_statement_jwt:,
                   udap_registration_response: JSON.generate(response_json),
                   udap_registration_grant_type:)
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(key.to_s)
    end
  end

  it 'fails if response values for immutable claims do not match values submitted in original request' do
    required_immutable_claims.each do |key|
      response_json = JSON.parse(correct_response)
      response_json[key] = 'CHANGED_VALUE'
      result = run(runnable,
                   udap_software_statement_json:,
                   udap_software_statement_jwt:,
                   udap_registration_response: JSON.generate(response_json),
                   udap_registration_grant_type:)
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(key.to_s)
    end
  end

  it 'passes if mutable claim values in registration response differ from original client request values' do
    required_mutable_claims.each do |key|
      response_json = JSON.parse(correct_response)
      response_json[key] = 'CHANGED VALUE'
      result = run(runnable,
                   udap_software_statement_json:,
                   udap_software_statement_jwt:,
                   udap_registration_response: JSON.generate(response_json),
                   udap_registration_grant_type:)
      expect(result.result).to eq('pass')
    end
  end

  it 'passes when all required values in registration response exactly match original client request values' do
    result = run(runnable,
                 udap_software_statement_json:,
                 udap_software_statement_jwt:,
                 udap_registration_response: correct_response,
                 udap_registration_grant_type:)

    expect(result.result).to eq('pass')
  end
end
