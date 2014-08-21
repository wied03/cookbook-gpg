require 'rspec'
$: << File.join(File.dirname(__FILE__), '../../..')
require 'libraries/helper_key_header'
require 'libraries/helper_gpg_parser'
require 'libraries/helper_gpg_interface'
require 'libraries/helper_gpg_keyring_specifier'
require 'libraries/helper_command_runner'

describe BswTech::Gpg::GpgInterface do
  before(:each) do
    @parser = double
    BswTech::Gpg::GpgParser.stub(:new).and_return @parser
    @gpg_command_executed = nil
    @gpg_mock_response = nil
    @gpg_input_supplied = nil
    @user_supplied = nil
    mock_command_runner = double
    allow(BswTech::CommandRunner).to receive(:new).and_return(mock_command_runner)
    allow(mock_command_runner).to receive(:run) do |command, as_user, input|
      @user_supplied = as_user
      @gpg_command_executed = command
      @gpg_input_supplied = input
      @gpg_mock_response
    end
    @gpg_interface = BswTech::Gpg::GpgInterface.new suppress_trustdb_check=false
    @dummy_secret_key_base64 = '-----BEGIN PGP PRIVATE KEY BLOCK-----'
  end

  it 'tells the parser to handle a base64 key properly' do
    # arrange
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return [key_header]
    @gpg_mock_response = 'gpg output here'

    # act
    result = @gpg_interface.get_key_header @dummy_secret_key_base64

    # assert
    expect(result).to eq(key_header)
    expect(@gpg_command_executed).to eq('gpg2 --with-fingerprint --with-colons')
    expect(@gpg_input_supplied).to eq @dummy_secret_key_base64
  end

  it 'complains if the base64 input does not contain public or private key header' do
    # arrange

    # act
    action = lambda {
      @gpg_interface.get_key_header 'foobar'
    }

    # assert
    expect(action).to raise_exception RuntimeError,
                                      "Supplied key contents did NOT start with '-----BEGIN PGP PUBLIC KEY BLOCK-----' or '-----BEGIN PGP PRIVATE KEY BLOCK-----'"
  end

  it 'complains if more than 1 key is returned via base64' do
    key_headers = [BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key),
                   BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :public_key)]
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return key_headers
    @gpg_mock_response = 'gpg output here'

    # act
    action = lambda { @gpg_interface.get_key_header @dummy_secret_key_base64 }

    # assert
    expect(action).to raise_exception "Multiple keys returned from a single base64 import should not happen!  Keys returned: #{key_headers}"
  end

  it 'can check current keys while suppressing the trust db check' do
    # arrange
    @gpg_interface = BswTech::Gpg::GpgInterface.new suppress_trustdb_check=true
    key_headers = [BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)]
    allow(@parser).to receive(:parse_output_ring).with('gpg output here').and_return key_headers
    @gpg_mock_response = 'gpg output here'

    # act
    result = @gpg_interface.get_current_installed_keys 'some_user', :secret_key

    # assert
    expect(result).to eq(key_headers)
    expect(@gpg_command_executed).to eq('gpg2 --no-auto-check-trustdb --list-secret-keys --with-fingerprint --with-colons')
  end

  it 'fetches current secret keys' do
    # arrange
    key_headers = [BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)]
    allow(@parser).to receive(:parse_output_ring).with('gpg output here').and_return key_headers
    @gpg_mock_response = 'gpg output here'

    # act
    result = @gpg_interface.get_current_installed_keys 'some_user', :secret_key

    # assert
    expect(result).to eq(key_headers)
    expect(@gpg_command_executed).to eq('gpg2 --list-secret-keys --with-fingerprint --with-colons')
  end

  it 'fetches current public keys' do
    # arrange
    key_headers = [BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :public_key)]
    allow(@parser).to receive(:parse_output_ring).with('gpg output here').and_return key_headers
    @gpg_mock_response = 'gpg output here'

    # act
    result = @gpg_interface.get_current_installed_keys 'some_user', :public_key

    # assert
    expect(result).to eq(key_headers)
    expect(@gpg_command_executed).to eq('gpg2 --list-keys --with-fingerprint --with-colons')
  end

  it 'fetches current secret keys from a non default ring' do
    # arrange
    key_headers = [BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)]
    allow(@parser).to receive(:parse_output_ring).with('gpg output here').and_return key_headers
    @gpg_mock_response = 'gpg output here'

    # act
    result = @gpg_interface.get_current_installed_keys 'some_user', :secret_key, 'stuff.gpg'

    # assert
    expect(result).to eq(key_headers)
    expect(@gpg_command_executed).to eq('gpg2 --no-default-keyring --secret-keyring stuff.gpg --list-secret-keys --with-fingerprint --with-colons')
  end

  it 'fetches current public keys from a non default ring' do
    # arrange
    key_headers = [BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :public_key)]
    allow(@parser).to receive(:parse_output_ring).with('gpg output here').and_return key_headers
    @gpg_mock_response = 'gpg output here'

    # act
    result = @gpg_interface.get_current_installed_keys 'some_user', :public_key, 'stuff.gpg'

    # assert
    expect(result).to eq(key_headers)
    expect(@gpg_command_executed).to eq('gpg2 --no-default-keyring --keyring stuff.gpg --list-keys --with-fingerprint --with-colons')
  end

  it 'imports keys properly into a default keyring' do
    # arrange
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return [key_header]
    @gpg_mock_response = 'gpg output here'

    # act
    @gpg_interface.import_keys 'some_user', @dummy_secret_key_base64

    # assert
    expect(@gpg_command_executed).to eq 'gpg2 --import'
    expect(@gpg_input_supplied).to eq @dummy_secret_key_base64
  end

  it 'imports keys while suppressing the trustdb check' do
    # arrange
    @gpg_interface = BswTech::Gpg::GpgInterface.new suppress_trustdb_check=true
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return [key_header]
    @gpg_mock_response = 'gpg output here'

    # act
    @gpg_interface.import_keys 'some_user', @dummy_secret_key_base64

    # assert
    expect(@gpg_command_executed).to eq 'gpg2 --no-auto-check-trustdb --import'
    expect(@gpg_input_supplied).to eq @dummy_secret_key_base64
  end

  it 'imports keys into a non-default keyring' do
    # arrange
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return [key_header]
    @gpg_mock_response = 'gpg output here'

    # act
    @gpg_interface.import_keys username='some_user',
                               base64=@dummy_secret_key_base64,
                               keyring='stuff.gpg'

    # assert
    expect(@gpg_command_executed).to eq 'gpg2 --no-default-keyring --secret-keyring stuff.gpg --import'
    expect(@gpg_input_supplied).to eq @dummy_secret_key_base64
  end

  it 'imports trust properly with a default keyring' do
    # arrange
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return [key_header]
    @gpg_mock_response = 'gpg output here'

    # act
    @gpg_interface.import_trust 'some_user', @dummy_secret_key_base64

    # assert
    expect(@gpg_command_executed).to eq 'gpg2 --import-ownertrust'
    expect(@gpg_input_supplied).to eq "fp:6:\n"
  end

  it 'imports trust properly with a non-default keyring' do
    # arrange
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return [key_header]
    @gpg_mock_response = 'gpg output here'

    # act
    @gpg_interface.import_trust username='some_user',
                                base64=@dummy_secret_key_base64,
                                keyring='stuff.gpg'

    # assert
    expect(@gpg_command_executed).to eq 'gpg2 --no-default-keyring --secret-keyring stuff.gpg --import-ownertrust'
    expect(@gpg_input_supplied).to eq "fp:6:\n"
  end

  it 'imports trust while suppressing the trustdb check' do
    # arrange
    @gpg_interface = BswTech::Gpg::GpgInterface.new suppress_trustdb_check=true
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return [key_header]
    @gpg_mock_response = 'gpg output here'

    # act
    @gpg_interface.import_trust username='some_user',
                                base64=@dummy_secret_key_base64,
                                keyring='stuff.gpg'

    # assert
    expect(@gpg_command_executed).to eq 'gpg2 --no-auto-check-trustdb --no-default-keyring --secret-keyring stuff.gpg --import-ownertrust'
    expect(@gpg_input_supplied).to eq "fp:6:\n"
  end

  it 'deletes keys properly' do
    # arrange
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)

    # act
    @gpg_interface.delete_keys username='some_user',
                               key_header_to_delete=key_header

    # assert
    expect(@gpg_command_executed).to eq 'gpg2 --delete-secret-and-public-key --batch --yes fp'
  end

  it 'deletes while suppressing the trustdb check' do
    # arrange
    @gpg_interface = BswTech::Gpg::GpgInterface.new suppress_trustdb_check=true
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)

    # act
    @gpg_interface.delete_keys username='some_user',
                               key_header_to_delete=key_header

    # assert
    expect(@gpg_command_executed).to eq 'gpg2 --no-auto-check-trustdb --delete-secret-and-public-key --batch --yes fp'
  end

  it 'deletes keys properly with a non-default keyring' do
    # arrange
    key_header = BswTech::Gpg::KeyHeader.new('fp', 'username', 'id', :secret_key)

    # act
    @gpg_interface.delete_keys username='some_user',
                               key_header_to_delete=key_header,
                               keyring='stuff.gpg'

    # assert
    expect(@gpg_command_executed).to eq 'gpg2 --no-default-keyring --secret-keyring stuff.gpg --delete-secret-and-public-key --batch --yes fp'
  end
end
