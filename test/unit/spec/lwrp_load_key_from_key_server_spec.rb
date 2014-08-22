# Encoding: utf-8

require_relative 'spec_helper'
$: << File.join(File.dirname(__FILE__), '../../..')
require 'libraries/helper_gpg_interface'
require 'libraries/helper_key_header'

describe 'gpg::lwrp:load_key_from_key_server' do
  include BswTech::ChefSpec::LwrpTestHelper

  def cookbook_under_test
    'bsw_gpg'
  end

  def lwrps_under_test
    'load_key_from_key_server'
  end

  def stub_hkp_retrieval(key_id, expected_key_server, key_contents)
    key_fetcher = double
    BswTech::Hkp::KeyFetcher.stub(:new).and_return key_fetcher
    allow(key_fetcher).to receive(:fetch_key).with(expected_key_server, key_id).and_return key_contents
  end

  %w(key_server key_id).each do |attr_to_include|
    it "fails if we only supply #{attr_to_include}" do
      # arrange

      # act
      action = lambda {
        temp_lwrp_recipe <<-EOF
          bsw_gpg_load_key_from_key_server 'some key' do
            #{attr_to_include} 'value'
          end
        EOF
      }

      # assert
      expect(action).to raise_exception Chef::Exceptions::ValidationFailed
    end
  end

  it 'fetches a public key from the key server properly and installs it if not there' do
    # arrange
    stub_gpg_interface(draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                         username='the username',
                                                         id='the_key_id',
                                                         type=:public_key))
    stub_hkp_retrieval(key_id='the_key_id',
                       expected_key_server='some.key.server',
                       key_contents="-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoobar")
    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_key_server 'some key' do
        key_server 'some.key.server'
        key_id 'the_key_id'
        for_user 'root'
      end
    EOF

    # assert
    expect(@base64_used).to eq("-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoobar")
    expect(@current_key_checks).to eq([{
                                           :username => 'root',
                                           :keyring => :default,
                                           :type => :public_key
                                       }])
    # noinspection RubyResolve
    expect(@keys_deleted).to be_empty
    expect(@keys_imported).to eq [{
                                      :base64 => "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoobar",
                                      :keyring => :default,
                                      :username => 'root'
                                  }]
    expect(@keytrusts_imported).to eq []
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_key_server', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'fetches a public key from the key server properly and does not install it if its already there' do
    # arrange
    key = BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                      username='the username',
                                      id='the_key_id',
                                      type=:public_key)
    stub_gpg_interface(current=[key], draft=key)
    stub_hkp_retrieval(key_id='the_key_id',
                       expected_key_server='some.key.server',
                       key_contents="-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoobar")

    # act
    temp_lwrp_recipe <<-EOF
        bsw_gpg_load_key_from_key_server 'some key' do
          key_server 'some.key.server'
          key_id 'the_key_id'
          for_user 'root'
        end
    EOF

    # assert
    expect(@base64_used).to eq("-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoobar")
    expect(@current_key_checks).to eq([{
                                           :username => 'root',
                                           :keyring => :default,
                                           :type => :public_key
                                       }])
    expect(@keys_deleted).to be_empty
    expect(@keys_imported).to be_empty
    expect(@keytrusts_imported).to be_empty
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_key_server', 'some key'
    expect(resource.updated_by_last_action?).to eq(false)
  end
end
