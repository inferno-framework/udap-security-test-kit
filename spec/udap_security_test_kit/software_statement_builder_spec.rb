require_relative '../../lib/udap_security_test_kit/software_statement_builder'

RSpec.describe UDAPSecurityTestKit::SoftwareStatementBuilder do
  let(:iss_ac) { 'https://inferno.org/ac_client' }
  let(:iss_cc) { 'https://inferno.org/cc_client' }
  let(:aud) { 'http://example.org/registration' }
  let(:grant_types_ac) { 'authorization_code' }
  let(:grant_types_cc) { 'client_credentials' }
  let(:scope_ac) { 'user/*.read' }
  let(:scope_cc) { 'system/*.read' }

  def validate_common_payload_claims(payload)
    expect(payload[:aud]).to eq(aud)
    expect(payload[:iat]).to be_present
    expect(payload[:exp]).to be <= payload[:iat] + (60 * 5)
    expect(payload[:jti]).to be_present
    expect(payload[:contacts]).to be_present
    expect(payload[:logo_uri]).to be_present
    expect(payload[:token_endpoint_auth_method]).to eq('private_key_jwt')
  end

  describe '.build_payload' do
    context 'when client is using authorization_code flow' do
      it 'contains the required fields' do
        payload = described_class.build_payload(iss_ac, aud, grant_types_ac, scope_ac)

        validate_common_payload_claims(payload)
        expect(payload[:iss]).to eq(iss_ac)
        expect(payload[:sub]).to eq(iss_ac)
        expect(payload[:client_name]).to eq('Inferno UDAP Authorization Code Test Client')
        expect(payload[:redirect_uris]).to be_present
        expect(payload[:redirect_uris].empty?).to be false
        expect(payload[:grant_types]).to eq([grant_types_ac])
        expect(payload[:response_types]).to eq(['code'])
        expect(payload[:scope]).to eq(scope_ac)
      end
    end

    context 'when client is using client_credentials flow' do
      it 'contains the required fields' do
        payload = described_class.build_payload(iss_cc, aud, grant_types_cc, scope_cc)

        validate_common_payload_claims(payload)
        expect(payload[:iss]).to eq(iss_cc)
        expect(payload[:sub]).to eq(iss_cc)
        expect(payload[:client_name]).to eq('Inferno UDAP Client Credentials Test Client')
        expect(payload[:redirect_uris]).to_not be_present
        expect(payload[:grant_types]).to eq([grant_types_cc])
        expect(payload[:response_types]).to_not be_present
        expect(payload[:scope]).to eq(scope_cc)
      end
    end
  end
end
