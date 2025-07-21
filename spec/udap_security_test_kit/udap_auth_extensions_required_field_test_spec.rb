require_relative '../../lib/udap_security_test_kit/udap_auth_extensions_required_field_test'

RSpec.describe UDAPSecurityTestKit::UDAPAuthExtensionsRequiredFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_auth_extensions_required_field') }

  it 'skips if udap_authorization_extensions_supported field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('skip')
  end

  it 'omits if udap_authorization_extensions_supported field is present but empty' do
    config = { udap_authorization_extensions_supported: [] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('omit')
  end

  context 'when udap_authorization_extensions_supported is present and not empty' do
    it 'fails if udap_authorization_extensions_required field is missing' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json)

      expect(result.result).to eq('fail')
    end

    it 'passes if udap_authorization_extensions_required field is an empty array' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'], udap_authorization_extensions_required: [] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'passes if array includes a string' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'],
                 udap_authorization_extensions_required: ['hl7-b2b'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json)

      expect(result.result).to eq('pass')
    end
  end
end
