require_relative '../../lib/udap_security/udap_client_assertion_payload_builder'

RSpec.describe UDAPSecurity::UDAPClientAssertionPayloadBuilder do
  let(:iss) { 'https://example.org/sample-iss' }
  let(:aud) { 'http://example.org/token' }
  let(:extensions) do
    {
      'hl7-b2b' => {
        'version' => '1',
        'subject_name' => 'UDAP Test Kit',
        'organization_name' => 'Inferno Framework',
        'organization_id' => 'https://inferno-framework.github.io/',
        'purpose_of_use' => ['SYSDEV']
      }
    }
  end

  def validate_common_payload_claims(payload)
    expect(payload[:aud]).to eq(aud)
    expect(payload[:sub]).to eq(iss)
    expect(payload[:iat]).to be_present
    expect(payload[:exp]).to be <= payload[:iat] + (60 * 5)
    expect(payload[:jti]).to be_present
  end

  describe '.build' do
    context 'when client is using authorization_code flow' do
      it 'contains the required fields' do
        # hl7-b2b extensions only required for client_credentials flow
        payload = described_class.build(iss, aud, nil)

        validate_common_payload_claims(payload)
        expect(payload[:extensions]).to be_blank
      end
    end

    context 'when client is using client_credentials flow' do
      it 'contains the required fields' do
        payload = described_class.build(iss, aud, extensions)

        validate_common_payload_claims(payload)
        expect(payload[:extensions]).to be_present
        expect(payload[:extensions]).to eq extensions
      end
    end
  end
end
