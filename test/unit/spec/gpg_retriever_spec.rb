require 'rspec'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'key_details'
require 'gpg_parser'
require 'gpg_retriever'

describe BswTech::Gpg::GpgRetriever do
  before(:each) do
    @parser = double()
    BswTech::Gpg::GpgParser.stub(:new).and_return @parser
    @retriever = BswTech::Gpg::GpgRetriever.new
    @gpg_command_executed = nil
    @gpg_mock_response = nil
    @gpg_input_supplied = nil
    @gpg_mock_executor = lambda do |*args|
      @gpg_command_executed = args[0]
      @gpg_input_supplied = args[1] if args.length > 1
      @gpg_mock_response
    end
  end

  it 'fetches base 64/external keys that are secret' do
    # arrange
    result = [BswTech::Gpg::KeyDetails.new('fp', 'username', 'id', :secret_key)]
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return result
    @gpg_mock_response = 'gpg output here'

    # act
    result = @retriever.get_key_info_from_base64 @gpg_mock_executor, :secret_key, 'foobar base64'

    # assert
    expect(result).to eq(result)
    expect(@gpg_command_executed).to eq('gpg2 --with-fingerprint --with-colons')
    expect(@gpg_input_supplied).to eq('foobar base64')
  end

  it 'fetches base 64/external keys that are public' do
    # arrange
    result = [BswTech::Gpg::KeyDetails.new('fp', 'username', 'id', :public_key)]
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return result
    @gpg_mock_response = 'gpg output here'

    # act
    result = @retriever.get_key_info_from_base64 @gpg_mock_executor, :public_key, 'foobar base64'

    # assert
    expect(result).to eq(result)
    expect(@gpg_command_executed).to eq('gpg2 --with-fingerprint --with-colons')
    expect(@gpg_input_supplied).to eq('foobar base64')
  end

  it 'complains if base64/external key is public and type specified is secret' do
    # arrange
    result = [BswTech::Gpg::KeyDetails.new('fp', 'username', 'id', :public_key)]
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return result
    @gpg_mock_response = 'gpg output here'

    # act
    action = lambda { @retriever.get_key_info_from_base64 @gpg_mock_executor, :secret_key, 'foobar base64' }

    # assert
    expect(action).to raise_exception "Key #{result} is a public key but you're trying to import a secret key"
  end

  it 'complains if base64/external key is secret and type specified is public' do
    # arrange
    result = [BswTech::Gpg::KeyDetails.new('fp', 'username', 'id', :secret_key)]
    allow(@parser).to receive(:parse_output_external).with('gpg output here').and_return result
    @gpg_mock_response = 'gpg output here'

    # act
    action = lambda { @retriever.get_key_info_from_base64 @gpg_mock_executor, :public_key, 'foobar base64' }

    # assert
    expect(action).to raise_exception "Key #{result} is a secret key but you're trying to import a public key"
  end

  it 'fetches current secret keys' do
    # arrange
    result = [BswTech::Gpg::KeyDetails.new('fp', 'username', 'id', :secret_key)]
    allow(@parser).to receive(:parse_output_ring).with('gpg output here').and_return result
    @gpg_mock_response = 'gpg output here'

    # act
    result = @retriever.get_current_installed_keys @gpg_mock_executor, :secret_key

    # assert
    expect(result).to eq(result)
    expect(@gpg_command_executed).to eq('gpg2 --list-secret-keys --with-fingerprint --with-colons')
  end

  it 'fetches current public keys' do
    # arrange
    result = [BswTech::Gpg::KeyDetails.new('fp', 'username', 'id', :public_key)]
    allow(@parser).to receive(:parse_output_ring).with('gpg output here').and_return result
    @gpg_mock_response = 'gpg output here'

    # act
    result = @retriever.get_current_installed_keys @gpg_mock_executor, :public_key

    # assert
    expect(result).to eq(result)
    expect(@gpg_command_executed).to eq('gpg2 --list-keys --with-fingerprint --with-colons')
  end
end
