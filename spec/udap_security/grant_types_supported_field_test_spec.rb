require_relative '../../lib/udap_security/grant_types_supported_field_test'

RSpec.describe UDAPSecurityTestKit::GrantTypesSupportedFieldTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_grant_types_supported_field') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }
  let(:required_flow_type) { [''] }

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

  context 'when the server can support any authorization flow(s)' do
    it 'fails if field is not present' do
      config = {}

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('fail')
    end

    it 'fails if grant_types_supported is not an array' do
      config = { grant_types_supported: 'http://abc' }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be an Array/)
    end

    it 'fails if array is present but empty' do
      config = { grant_types_supported: [] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('fail')
    end

    it 'fails if grant_types_supported is an array with a non-string element' do
      config = { grant_types_supported: ['http://abc', 1] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Array of strings/)
    end

    it 'fails if grant_types_supported includes refresh_token without authorization_code' do
      config = { grant_types_supported: ['refresh_token'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/authorization_code/)
    end

    it 'passes if grant_types_supported includes a valid grant type' do
      config = { grant_types_supported: ['client_credentials'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: [''])

      expect(result.result).to eq('pass')
    end
  end

  context 'when the server must support authorization_code flow' do
    it 'fails if authorization_code is not a supported grant type' do
      config = { grant_types_supported: ['client_credentials'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: ['authorization_code'])

      expect(result.result).to eq('fail')
    end

    it 'passes if authorization_code is a supported grant type' do
      config = { grant_types_supported: ['client_credentials', 'authorization_code'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: ['authorization_code'])

      expect(result.result).to eq('pass')
    end
  end

  context 'when the server must support client_credentials' do
    it 'fails if client_credentials is not a supported grant type' do
      config = { grant_types_supported: ['authorization_code'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: ['client_credentials'])

      expect(result.result).to eq('fail')
    end

    it 'passes if client_credentials is a supported grant type' do
      config = { grant_types_supported: ['client_credentials'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: ['client_credentials'])

      expect(result.result).to eq('pass')
    end
  end

  context 'when the server must support both authorization_code and client_credentials grant types' do
    it 'fails if neither authorization_code nor client_credentials is a supported grant type' do
      config = { grant_types_supported: ['other_grant_type'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: [
                     'client_credentials',
                     'authorization_code'
                   ])

      expect(result.result).to eq('fail')
    end

    it 'fails if only one of the required grant types is supported' do
      config = { grant_types_supported: ['authorization_code', 'other_grant_type'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: [
                     'client_credentials',
                     'authorization_code'
                   ])

      expect(result.result).to eq('fail')
    end

    it 'passes when both grant types are supported' do
      config = { grant_types_supported: ['authorization_code', 'client_credentials'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: [
                     'client_credentials',
                     'authorization_code'
                   ])

      expect(result.result).to eq('pass')
    end
  end
end
