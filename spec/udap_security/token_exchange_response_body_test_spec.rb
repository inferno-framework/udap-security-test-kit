require_relative '../../lib/udap_security_test_kit/token_exchange_response_body_test'

RSpec.describe UDAPSecurityTestKit::TokenExchangeResponseBodyTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_token_exchange_response_body') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }

  let(:required_parameters) do
    [
      'access_token',
      'token_type'
    ]
  end

  let(:correct_response) do
    {
      'access_token' => 'example_access_token',
      'token_type' => 'Bearer'
    }
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

  it 'fails if response is not valid JSON' do
    invalid_response_body = '{invalid_key: invalid_value}'
    result = run(runnable, token_response_body: invalid_response_body)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/valid JSON/)
  end

  it 'fails if required parameters are not present' do
    required_parameters.each do |key|
      response = correct_response.clone
      response.delete(key)
      result = run(runnable, token_response_body: JSON.generate(response))
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(key)
    end
  end

  it 'fails if required parameters have blank/empty values' do
    required_parameters.each do |key|
      response = correct_response.clone
      response[key] = ''
      result = run(runnable, token_response_body: JSON.generate(response))
      expect(result.result).to eq('fail')
      expect(result.result_message).to match(key)
    end
  end

  it 'passes when response contains all required values' do
    result = run(runnable, token_response_body: JSON.generate(correct_response))

    expect(result.result).to eq('pass')
  end
end
