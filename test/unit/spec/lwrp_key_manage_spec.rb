# Encoding: utf-8

require_relative 'spec_helper'
require 'chef-vault'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'gpg_retriever'
require 'key_details'

describe 'gpg::lwrp:key_manage' do
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
    ['load_key_from_string', 'load_key_from_chef']
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

  it 'complains if the base64 input does not contain public or private key header' do
    # arrange
    stub_retriever(draft=nil)
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

    # act
    action = lambda {
      temp_lwrp_recipe <<-EOF
          bsw_gpg_load_key_from_string 'some key' do
            key_contents 'no header in here'
            for_user 'root'
          end
      EOF
    }

    # assert
    expect(action).to raise_exception RuntimeError,
                                      "bsw_gpg_load_key_from_string[some key] (lwrp_gen::default line 1) had an error: RuntimeError: Supplied key contents did NOT start with '-----BEGIN PGP PUBLIC KEY BLOCK-----' or '-----BEGIN PGP PRIVATE KEY BLOCK-----'"
  end

  it 'complains if the base64 input contains more than 1 public key' do
    # arrange
    stub_retriever(draft=nil)
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

    # act
    action = lambda {
      temp_lwrp_recipe <<-EOF
        bsw_gpg_load_key_from_string 'some key' do
          key_contents "-----BEGIN PGP PUBLIC KEY BLOCK-----\nstuff\n-----END PGP PUBLIC KEY BLOCK-----\n-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----"
          for_user 'root'
        end
      EOF
    }

    # assert
    expect(action).to raise_exception RuntimeError,
                                      'bsw_gpg_load_key_from_string[some key] (lwrp_gen::default line 1) had an error: RuntimeError: Supplied key contents has 2 public_key values, only 1 is allowed'
  end

  it 'complains if the base64 input contains more than 1 secret key' do
    # arrange
    stub_retriever(draft=nil)
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

    # act
    action = lambda {
      temp_lwrp_recipe <<-EOF
        bsw_gpg_load_key_from_string 'some key' do
          key_contents "-----BEGIN PGP PRIVATE KEY BLOCK-----\nstuff\n-----END PGP PRIVATE KEY BLOCK-----\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n-----END PGP PRIVATE KEY BLOCK-----"
          for_user 'root'
        end
      EOF
    }

    # assert
    expect(action).to raise_exception RuntimeError,
                                      'bsw_gpg_load_key_from_string[some key] (lwrp_gen::default line 1) had an error: RuntimeError: Supplied key contents has 2 secret_key values, only 1 is allowed'
  end

  it 'complains if the base64 input contains a public and secret key' do
    # arrange
    stub_retriever(draft=nil)
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

    # act
    action = lambda {
      temp_lwrp_recipe <<-EOF
        bsw_gpg_load_key_from_string 'some key' do
          key_contents "-----BEGIN PGP PUBLIC KEY BLOCK-----\nstuff\n-----END PGP PUBLIC KEY BLOCK-----\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n-----END PGP PRIVATE KEY BLOCK-----"
          for_user 'root'
        end
      EOF
    }

    # assert
    expect(action).to raise_exception RuntimeError,
                                      'bsw_gpg_load_key_from_string[some key] (lwrp_gen::default line 1) had an error: RuntimeError: Supplied key contents has both secret and public keys, only 1 key is allowed'
  end

  it 'works properly when importing a secret key that is not already there' do
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

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PRIVATE KEY BLOCK-----'
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
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'works properly when importing a public key that is not already there' do
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                      username='the username',
                                                      id='the id',
                                                      type=:public_key))

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

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PUBLIC KEY BLOCK-----'
        for_user 'root'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:public_key)
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
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
    input_specified.should == {'gpg2 --import' => '-----BEGIN PGP PUBLIC KEY BLOCK-----',
                               'gpg2 --import-ownertrust' => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'does not do anything if the correct public key is already there' do
    key = BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                       username='the username',
                                       id='the id',
                                       type=:public_key)
    stub_retriever(current=[key], draft=key)
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PUBLIC KEY BLOCK-----'
        for_user 'root'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:public_key)
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    executed_cmdline = executed_command_lines
    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"']
    users = @shell_outs.map { |e| e.user }.uniq
    users.should == ['root']
    env = @shell_outs.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil]
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {}
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(false)
  end

  it 'does not do anything if the correct secret key is already there' do
    # arrange
    key = BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                       username='the username',
                                       id='the id',
                                       type=:secret_key)
    stub_retriever(current=[key], draft=key)
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PRIVATE KEY BLOCK-----'
        for_user 'root'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:secret_key)
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    executed_cmdline = executed_command_lines
    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"']
    users = @shell_outs.map { |e| e.user }.uniq
    users.should == ['root']
    env = @shell_outs.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil]
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {}
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(false)
  end

  it 'does update the key if a different public key is already there' do
    # arrange
    current_key = BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                               username='the username',
                                               id='the id',
                                               type=:public_key)
    new_key = BswTech::Gpg::KeyDetails.new(fingerprint='5D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                           username='the username 2',
                                           id='the id',
                                           type=:public_key)
    stub_retriever(current=[current_key], draft=new_key)
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

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PUBLIC KEY BLOCK-----'
        for_user 'root'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:public_key)
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
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
    input_specified.should == {'gpg2 --import' => '-----BEGIN PGP PUBLIC KEY BLOCK-----',
                               'gpg2 --import-ownertrust' => "5D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'does update the key if a different secret key is already there' do
    # arrange
    current_key = BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                               username='the username',
                                               id='the id',
                                               type=:secret_key)
    new_key = BswTech::Gpg::KeyDetails.new(fingerprint='5D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                           username='the username 2',
                                           id='the id',
                                           type=:secret_key)
    stub_retriever(current=[current_key], draft=new_key)
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

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PRIVATE KEY BLOCK-----'
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
                               'gpg2 --import-ownertrust' => "5D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end


  it 'installs they key properly when run as a different user' do
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                      username='the username',
                                                      id='the id',
                                                      type=:secret_key))
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~someone_else"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/someone_else')
        when 'gpg2 --import'
          shell_out.stub!(:error!)
        when 'gpg2 --import-ownertrust'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PRIVATE KEY BLOCK-----'
        for_user 'someone_else'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:secret_key)
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    executed_cmdline = executed_command_lines
    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~someone_else"',
                                     'gpg2 --import',
                                     'gpg2 --import-ownertrust']
    users = @shell_outs.map { |e| e.user }.uniq
    users.should == ['someone_else']
    env = @shell_outs.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/someone_else']
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {'gpg2 --import' => '-----BEGIN PGP PRIVATE KEY BLOCK-----',
                               'gpg2 --import-ownertrust' => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'overwrites the existing public key for the user if the fingerprint has changed' do
    # arrange
    current = BswTech::Gpg::KeyDetails.new(fingerprint='6D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                           username='the username',
                                           id='the id',
                                           type=:public_key)
    stub_retriever(current=[current],
                   draft=BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                      username='the username',
                                                      id='the id',
                                                      type=:public_key))
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --delete-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9'
          shell_out.stub!(:error!)
        when 'gpg2 --import'
          shell_out.stub!(:error!)
        when 'gpg2 --import-ownertrust'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PUBLIC KEY BLOCK-----'
        for_user 'root'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:public_key)
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    executed_cmdline = executed_command_lines
    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"',
                                     'gpg2 --delete-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                     'gpg2 --import',
                                     'gpg2 --import-ownertrust']
    users = @shell_outs.map { |e| e.user }.uniq
    users.should == ['root']
    env = @shell_outs.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/root']
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {'gpg2 --import' => '-----BEGIN PGP PUBLIC KEY BLOCK-----',
                               'gpg2 --import-ownertrust' => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'overwrites the existing private key for the user if the fingerprint has changed' do
    # arrange
    current = BswTech::Gpg::KeyDetails.new(fingerprint='6D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                           username='the username',
                                           id='the id',
                                           type=:secret_key)
    stub_retriever(current=[current],
                   draft=BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                      username='the username',
                                                      id='the id',
                                                      type=:secret_key))
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --delete-secret-and-public-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9'
          shell_out.stub!(:error!)
        when 'gpg2 --import'
          shell_out.stub!(:error!)
        when 'gpg2 --import-ownertrust'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PRIVATE KEY BLOCK-----'
        for_user 'root'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:secret_key)
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    executed_cmdline = executed_command_lines
    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"',
                                     'gpg2 --delete-secret-and-public-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9',
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
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'allows working with public key fingerprints from the recipe based on a PEM cert' do
    # arrange
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='7B11C14106673B5346A65351F44B4C6833AE3E6C',
                                                      username='pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>',
                                                      id='the id',
                                                      type=:public_key))
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe <<-EOF
      key = get_draft_key_from_string '-----BEGIN PGP PUBLIC KEY BLOCK-----'
      file '/some/dummy/file' do
        content key.fingerprint
      end

      file '/some/dummy/file2' do
        content key.username
      end
    EOF

    # assert
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    expect(@chef_run).to render_file('/some/dummy/file').with_content('7B11C14106673B5346A65351F44B4C6833AE3E6C')
    expect(@chef_run).to render_file('/some/dummy/file2').with_content('pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>')
  end

  it 'allows working with private key fingerprints from the recipe based on a PEM cert' do
    # arrange
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='7B11C14106673B5346A65351F44B4C6833AE3E6C',
                                                      username='pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>',
                                                      id='the id',
                                                      type=:secret_key))
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe <<-EOF
      key = get_draft_key_from_string '-----BEGIN PGP PRIVATE KEY BLOCK-----'
      file '/some/dummy/file' do
        content key.fingerprint
      end

      file '/some/dummy/file2' do
        content key.username
      end
    EOF

    # assert
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    expect(@chef_run).to render_file('/some/dummy/file').with_content('7B11C14106673B5346A65351F44B4C6833AE3E6C')
    expect(@chef_run).to render_file('/some/dummy/file2').with_content('pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>')
  end

  it 'allows working with public key fingerprints from the recipe based on a cookbook file' do
    # arrange
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                      username='BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>',
                                                      id='the id',
                                                      type=:public_key))
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end
    dev_environment = File.join(cookbook_path, 'files', 'default', 'dev')
    FileUtils.mkdir_p dev_environment
    File.open File.join(dev_environment, 'thefile.pub'), 'w' do |f|
      f << '-----BEGIN PGP PUBLIC KEY BLOCK-----'
    end

    # act
    temp_lwrp_recipe <<-EOF
       key = get_draft_key_from_cookbook 'lwrp_gen', 'dev/thefile.pub'
       file '/some/dummy/file' do
         content key.fingerprint
       end

       file '/some/dummy/file2' do
         content key.username
       end
    EOF

    # assert
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    expect(@chef_run).to render_file('/some/dummy/file').with_content('4D1CF3288469F260C2119B9F76C95D74390AA6C9')
    expect(@chef_run).to render_file('/some/dummy/file2').with_content('BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>')
  end

  it 'allows working with private key fingerprints from the recipe based on a cookbook file' do
    # arrange
    stub_retriever(draft=BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                      username='BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>',
                                                      id='the id',
                                                      type=:secret_key))
    @stub_setup = lambda do |shell_out|
      @shell_outs << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end
    dev_environment = File.join(cookbook_path, 'files', 'default', 'dev')
    FileUtils.mkdir_p dev_environment
    File.open File.join(dev_environment, 'thefile.pub'), 'w' do |f|
      f << '-----BEGIN PGP PRIVATE KEY BLOCK-----'
    end

    # act
    temp_lwrp_recipe <<-EOF
       key = get_draft_key_from_cookbook 'lwrp_gen', 'dev/thefile.pub'
       file '/some/dummy/file' do
         content key.fingerprint
       end

       file '/some/dummy/file2' do
         content key.username
       end
    EOF

    # assert
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    expect(@chef_run).to render_file('/some/dummy/file').with_content('4D1CF3288469F260C2119B9F76C95D74390AA6C9')
    expect(@chef_run).to render_file('/some/dummy/file2').with_content('BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>')
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
      bsw_gpg_load_key_from_chef 'some key' do
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
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_chef', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end
end
