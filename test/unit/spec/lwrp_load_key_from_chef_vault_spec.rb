# Encoding: utf-8

require_relative 'spec_helper'
require 'chef-vault'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'gpg_retriever'
require 'key_details'

describe 'gpg::lwrp:load_key_from_chef_vault' do
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
    'load_key_from_chef_vault'
  end

  before {
    @stub_setup = nil
    original_new = Mixlib::ShellOut.method(:new)
    Mixlib::ShellOut.stub!(:new) do |*args|
      cmd = original_new.call(*args)
      cmd.stub!(:run_command)
      @stub_setup.call(cmd) if @stub_setup
      cmd
    end
    @gpg_retriever = double()
    BswTech::Gpg::GpgRetriever.stub(:new).and_return(@gpg_retriever)
    @current_type_checked = nil
    @external_type = nil
    @base64_used = nil
    @shell_outs = []
  }

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

  def executed_command_lines
    @shell_outs.inject({}) do |total, item|
      total[item.command] = item.input
      total
    end
  end

  it 'allows supplying Chef vault info for a private key directly as opposed to key contents' do
    # arrange
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                      username='the username',
                                                      id='the id',
                                                      type=:secret_key))
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --import'
          shell_out.stub!(:error!)
        when 'gpg2 --import-ownertrust'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end
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
    users = @shell_outs.map { |e| e.user }.uniq
    users.should == ['root']
    env = @shell_outs.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/root']
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {'gpg2 --import' => '-----BEGIN PGP PRIVATE KEY BLOCK-----',
                               'gpg2 --import-ownertrust' => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_chef_vault', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end
end
