# Encoding: utf-8

require_relative 'spec_helper'
require 'chef-vault'
$: << File.join(File.dirname(__FILE__), '../../..')
require 'libraries/helper_gpg_interface'
require 'libraries/helper_key_header'

describe 'gpg::lwrp:load_key_from_chef_vault' do
  include BswTech::ChefSpec::LwrpTestHelper

  def cookbook_under_test
    'bsw_gpg'
  end

  def lwrps_under_test
    'load_key_from_chef_vault'
  end

  %w(data_bag item json_key for_user).each do |attr_to_include|
    it "fails if we only supply #{attr_to_include}" do
      # arrange
      # act
      action = lambda {
        temp_lwrp_recipe <<-EOF
              bsw_gpg_load_key_from_chef_vault 'some key' do
                #{attr_to_include} 'value'
              end
        EOF
      }

      # assert
      expect(action).to raise_exception Chef::Exceptions::ValidationFailed
    end
  end

  it 'allows supplying Chef vault info for a private key directly as opposed to key contents' do
    # arrange
    stub_gpg_interface(draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                         username='the username',
                                                         id='the id',
                                                         type=:secret_key))
    stub_vault_entry = {'json_key' => '-----BEGIN PGP PRIVATE KEY BLOCK-----'}
    ChefVault::Item.stub!(:load).with('thedatabag', 'the_item').and_return stub_vault_entry

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_chef_vault 'some key' do
        data_bag 'thedatabag'
        item 'the_item'
        json_key 'json_key'
        for_user 'root'
      end
    EOF

    # assert
    expect(@current_key_checks).to eq([{
                                           :username => 'root',
                                           :keyring => :default,
                                           :type => :secret_key
                                       }])
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    # noinspection RubyResolve
    expect(@keys_deleted).to be_empty
    expect(@keys_imported).to eq [{
                                      :base64 => '-----BEGIN PGP PRIVATE KEY BLOCK-----',
                                      :keyring => :default,
                                      :username => 'root'
                                  }]
    expect(@keytrusts_imported).to eq [{
                                           :base64 => '-----BEGIN PGP PRIVATE KEY BLOCK-----',
                                           :keyring => :default,
                                           :username => 'root'
                                       }]
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_chef_vault', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end
end
