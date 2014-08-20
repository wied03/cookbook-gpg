# Encoding: utf-8

require_relative 'spec_helper'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'helper_gpg_retriever'
require 'helper_key_header'
require 'hkp'

describe 'gpg::lwrp:load_key_from_key_server' do
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

  def lwrps_under_test
    'load_key_from_key_server'
  end

  before {
    @gpg_retriever = double()
    BswTech::Gpg::GpgRetriever.stub(:new).and_return(@gpg_retriever)
    @current_type_checked = nil
    @external_type = nil
    @base64_used = nil
    @shell_outs = []
  }

  # TODO: Share this method
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

  # TODO: Share this method
  def executed_command_lines
    @shell_outs.inject({}) do |total, item|
      total[item.command] = item.input
      total
    end
  end

  # TODO: Share this method
  def setup_stub_commands(commands)
    @command_mocks = commands
    stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      command_text = shell_out.command
      matched_mock = @command_mocks.find { |mock| mock[:command] == command_text }
      if matched_mock
        shell_out.stub(:error!)
        shell_out.stub(:run_command) do
          if matched_mock[:expected_input] != shell_out.input
            fail "Expected input #{matched_mock[:expected_input]} but got #{shell_out.input}"
          end
        end
        output = matched_mock[:stdout] || ''
        shell_out.stub(:stdout).and_return(output)
      else
        shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end
    original_new = Mixlib::ShellOut.method(:new)
    Mixlib::ShellOut.stub(:new) do |*args|
      command = original_new.call(*args)
      stub_setup[command]
      command
    end
  end

# TODO: Share this method
  def verify_actual_commands_match_expected
    actual = executed_command_lines
    expected = @command_mocks.map { |cmd| cmd[:command] }
    actual.keys.should == expected
  end

  def stub_hkp_retrieval(key_id, expected_key_server, key_contents)
    hkp = double()
    Hkp.stub(:new) do |actual_key_server|
      fail "Expected key server #{expected_key_server} but got #{actual_key_server}" unless expected_key_server == actual_key_server
      hkp
    end
    allow(hkp).to receive(:fetch).with(key_id).and_return key_contents
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
    stub_retriever(draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
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
                                :command => 'gpg2 --import',
                                :expected_input => "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoobar"
                            },
                            {
                                :command => 'gpg2 --import-ownertrust',
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
    stub_retriever(current=[key], draft=key)
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
