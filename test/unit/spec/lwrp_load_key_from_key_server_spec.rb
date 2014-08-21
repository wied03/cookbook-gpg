# Encoding: utf-8

require_relative 'spec_helper'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'helper_gpg_interface'
require 'helper_key_header'

describe 'gpg::lwrp:load_key_from_key_server' do
  include BswTech::ChefSpec::LwrpTestHelper

  def cookbook_under_test
    'bsw_gpg'
  end

  def lwrps_under_test
    'load_key_from_key_server'
  end

  def stub_hkp_retrieval(key_id, expected_key_server, key_contents)
    key_fetcher = double()
    BswTech::Hkp::KeyFetcher.stub(:new).and_return key_fetcher
    allow(key_fetcher).to receive(:fetch_key).with(expected_key_server, key_id).and_return key_contents
  end

  ['key_server', 'key_id'].each do |attr_to_include|
    it "fails if we only supply #{attr_to_include}" do
      # arrange
      # Include all of this because for_user will try and run the provider's constructor
      setup_stub_commands([:command => '/bin/sh -c "echo -n ~value"', :stdout => '/home/root'])

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

    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import',
                                :expected_input => "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoobar"
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_key_server 'some key' do
        key_server 'some.key.server'
        key_id 'the_key_id'
        for_user 'root'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:public_key)
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq("-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoobar")
    verify_actual_commands_match_expected
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
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            }
                        ])
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
    expect(@current_type_checked).to eq(:public_key)
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq("-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoobar")
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_key_server', 'some key'
    expect(resource.updated_by_last_action?).to eq(false)
  end
end
