Gem::Specification.new do |spec|
  spec.name          = 'udap_security_test_kit'
  spec.version       = '0.1.1'
  spec.authors       = ['Stephen MacVicar']
  spec.email         = ['inferno@groups.mitre.org']
  spec.summary       = 'UDAP Security IG Test Kit'
  spec.description   = 'UDAP Security IG Test Kit'
  spec.homepage      = 'https://github.com/inferno-framework/udap-security-test-kit'
  spec.license       = 'Apache-2.0'
  spec.add_runtime_dependency 'inferno_core', '>= 0.4.2'
  spec.add_runtime_dependency 'jwt', '~> 2.3'
  spec.required_ruby_version = Gem::Requirement.new('>= 3.1.2')
  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/inferno-framework/udap-security-test-kit'
  spec.files = [
    Dir['lib/**/*.rb'],
    Dir['lib/**/*.json'],
    'LICENSE'
  ].flatten

  spec.require_paths = ['lib']
end
