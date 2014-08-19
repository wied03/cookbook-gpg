require_relative 'spec_helper'
require 'chef-vault'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'gpg_retriever'
require 'key_details'
require 'key_a_shared'

describe BswTech::Gpg::RecipeOrProvider do
  class DummyRunner
  end

  class SharedKeyModuleWrapper
    include BswTech::Gpg::RecipeOrProvider
    attr_accessor :run_context

    def initialize(run_context)
      @run_context = run_context
    end

    def run_command(*args)
      DummyRunner.new.run_command(*args)
    end

    def node

    end
  end

  before(:each) do
    @gpg_retriever = double()
    BswTech::Gpg::GpgRetriever.stub(:new).and_return(@gpg_retriever)
    @current_type_checked = nil
    @external_type = nil
    @base64_used = nil
    @runner = double()
    allow(DummyRunner).to receive(:new).and_return(@runner)
    result = double()
    allow(@runner).to receive(:run_command).and_return(result)
    allow(result).to receive(:stdout).and_return('')
    run_context = double()
    cookbook = double()
    allow(run_context).to receive(:cookbook_collection).and_return({generated_cookbook_name => cookbook})
    @logic = SharedKeyModuleWrapper.new run_context
    allow(cookbook).to receive(:preferred_filename_on_disk_location) do |a, b, filename|
      File.join(cookbook_path, 'files', 'default', filename)
    end
  end

  def stub_retriever(current=[], draft)
    allow(@gpg_retriever).to receive(:get_current_installed_keys) do |executor, type|
      @current_type_checked = type
      current
    end
    allow(@gpg_retriever).to receive(:get_key_info_from_base64) do |executor, type, base64|
      @external_type = type
      @base64_used = base64
      draft
    end
  end

  include BswTech::ChefSpec::LwrpTestHelper

  before {
    stub_resources
  }

  after(:each) {
    cleanup
  }

  def cookbook_under_test
    'bsw_gpg'
  end

  # def lwrps_under_test
  #   'load_key_from_string'
  # end

  it 'allows working with public key fingerprints from the recipe based on a PEM cert' do
    # arrange
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='7B11C14106673B5346A65351F44B4C6833AE3E6C',
                                                      username='pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>',
                                                      id='the id',
                                                      type=:public_key))


    # act
    result = @logic.get_draft_key_from_string '-----BEGIN PGP PUBLIC KEY BLOCK-----'

    # assert
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    expect(result.fingerprint).to eq('7B11C14106673B5346A65351F44B4C6833AE3E6C')
    expect(result.username).to eq('pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>')
  end

  it 'allows working with private key fingerprints from the recipe based on a PEM cert' do
    # arrange
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='7B11C14106673B5346A65351F44B4C6833AE3E6C',
                                                      username='pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>',
                                                      id='the id',
                                                      type=:secret_key))


    # act
    result = @logic.get_draft_key_from_string '-----BEGIN PGP PRIVATE KEY BLOCK-----'

    # assert
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    expect(result.fingerprint).to eq('7B11C14106673B5346A65351F44B4C6833AE3E6C')
    expect(result.username).to eq('pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>')
  end

  it 'allows working with public key fingerprints from the recipe based on a cookbook file' do
    # arrange
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                      username='BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>',
                                                      id='the id',
                                                      type=:public_key))
    dev_environment = File.join(cookbook_path, 'files', 'default', 'dev')
    FileUtils.mkdir_p dev_environment
    File.open File.join(dev_environment, 'thefile.pub'), 'w' do |f|
      f << '-----BEGIN PGP PUBLIC KEY BLOCK-----'
    end


    # act
    result = @logic.get_draft_key_from_cookbook 'lwrp_gen', 'dev/thefile.pub'

    # assert
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    expect(result.fingerprint).to eq('4D1CF3288469F260C2119B9F76C95D74390AA6C9')
    expect(result.username).to eq('BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>')
  end

  it 'allows working with private key fingerprints from the recipe based on a cookbook file' do
    # arrange
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                      username='BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>',
                                                      id='the id',
                                                      type=:secret_key))
    dev_environment = File.join(cookbook_path, 'files', 'default', 'dev')
    FileUtils.mkdir_p dev_environment
    File.open File.join(dev_environment, 'thefile.pub'), 'w' do |f|
      f << '-----BEGIN PGP PRIVATE KEY BLOCK-----'
    end


    # act
    result = @logic.get_draft_key_from_cookbook 'lwrp_gen', 'dev/thefile.pub'

    # assert
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    expect(result.fingerprint).to eq('4D1CF3288469F260C2119B9F76C95D74390AA6C9')
    expect(result.username).to eq('BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>')
  end
end