require 'rspec'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'uri'
require 'helper_hkp_fetcher'
require 'helper_gpg_retriever'
require 'helper_key_header'
require 'helper_gpg_parser'
require 'helper_gpg_keyring_specifier'
require 'chef/util/selinux'
require 'chef/mixin/shell_out'

describe BswTech::Hkp::KeyFetcher do
  include Chef::Mixin::ShellOut

  before(:each) do
    @test_key_id = '561F9B9CAC40B2F7'
    @expected_key = BswTech::Gpg::KeyHeader.new(fingerprint='16378A33A6EF16762922526E561F9B9CAC40B2F7',
                                                username='Phusion Automated Software Signing (Used by automated tools to sign software packages) <auto-software-signing@phusion.nl>',
                                                id='AC40B2F7',
                                                type=:public_key)

  end

  def check_result(actual)
    # TODO: Have a non gpg2 dependent test for this
    unless system 'which gpg2'
      pending 'Need gpg2 on your machine to test this'
    end
    retriever = BswTech::Gpg::GpgRetriever.new
    executor = lambda do |command, input|
      cmd = Mixlib::ShellOut.new(command, :input => input)
      cmd.run_command
      cmd.error!
      cmd.stdout
    end
    actual = retriever.get_key_info_from_base64(executor, :public_key, actual)
    expect(actual.fingerprint).to eq(@expected_key.fingerprint)
    expect(actual.username).to eq(@expected_key.username)
    expect(actual.id).to eq(@expected_key.id)
    expect(actual.type).to eq(@expected_key.type)
  end

  it 'correctly retrieves a key' do
    # arrange
    fetcher = BswTech::Hkp::KeyFetcher.new

    # act
    result = fetcher.fetch_key 'keyserver.ubuntu.com', @test_key_id

    # assert
    check_result result
  end

  it 'correctly retrieves a key with a full URL as the key server' do
    # arrange
    fetcher = BswTech::Hkp::KeyFetcher.new

    # act
    result = fetcher.fetch_key 'http://keyserver.ubuntu.com:11371', @test_key_id

    # assert
    check_result result
  end

  it 'complains if the key cannot be found' do
    # arrange
    fetcher = BswTech::Hkp::KeyFetcher.new

    # act
    action = lambda { fetcher.fetch_key 'keyserver.ubuntu.com', 'blah' }

    # assert
    expect(action).to raise_exception "Contacted key server OK, but key ID 'blah' was not found"
  end

  it 'complains if the key server cannot be contacted' do
    # arrange
    fetcher = BswTech::Hkp::KeyFetcher.new

    # act
    action = lambda { fetcher.fetch_key 'blah', 'key_id' }

    # assert
    expect(action).to raise_exception /Unable to contact key server 'http:\/\/blah:11371\/pks\/lookup\?options=mr&op=get&search=0xkey_id', details: getaddrinfo.*/
  end
end