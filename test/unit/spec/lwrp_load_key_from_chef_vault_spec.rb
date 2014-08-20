# Encoding: utf-8

require_relative 'spec_helper'
require 'chef-vault'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'helper_gpg_retriever'
require 'helper_key_header'

describe 'gpg::lwrp:load_key_from_chef_vault' do
  include BswTech::ChefSpec::LwrpTestHelper

  def cookbook_under_test
    'bsw_gpg'
  end

  def lwrps_under_test
    'load_key_from_chef_vault'
  end

  ['data_bag', 'item', 'json_key', 'for_user'].each do |attr_to_include|
    it "fails if we only supply #{attr_to_include}" do
      # arrange
      # Include all of this because for_user will try and run the provider's constructor
      setup_stub_commands([:command => '/bin/sh -c "echo -n ~value"', :stdout => '/home/root'])
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
    stub_retriever(draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:secret_key))
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --import',
                                :expected_input => '-----BEGIN PGP PRIVATE KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])
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
    expect(@current_type_checked).to eq(:secret_key)
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    executed_cmdline = executed_command_lines
    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"',
                                     'gpg2 --import',
                                     'gpg2 --import-ownertrust']
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_chef_vault', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end
end
