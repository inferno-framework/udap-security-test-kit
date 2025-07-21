require_relative '../../lib/udap_security_test_kit/udap_auth_extensions_supported_field_test'

RSpec.describe UDAPSecurityTestKit::UDAPAuthExtensionsSupportedFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_auth_extensions_supported_field') }
  let(:required_flow_type) { [''] }

  context 'when the server can support any authorization flow(s)' do
    it 'fails if field is not present' do
      config = {}

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('fail')
    end

    it 'fails if udap_authorization_extensions_supported value is not an array' do
      config = { udap_authorization_extensions_supported: 'hl7-b2b' }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('fail')
    end

    it 'passes if array is empty' do
      config = { udap_authorization_extensions_supported: [] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('pass')
    end

    it 'passes if array includes a string' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('pass')
    end
  end

  context 'when the server must support client_credentials flow' do
    it 'fails if hl7-b2b extension is not supported' do
      config = { udap_authorization_extensions_supported: [] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: ['client_credentials'])

      expect(result.result).to eq('fail')
    end

    it 'passes if hl7-b2b extension is supported' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: ['client_credentials'])

      expect(result.result).to eq('pass')
    end
  end
end
