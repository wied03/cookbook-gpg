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
    'key_manage'
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
  }

  def stub_retriever(current, draft)
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

  it 'works properly when importing a private key that is not already there' do
    # arrange
    stub_retriever([],
                   BswTech::Gpg::KeyDetails.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                 username='the username',
                                                 id='the id',
                                                 type=:secret_key))
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
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
      bsw_gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:secret_key)
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('thekeybitshere')
    executed_cmdline = executed.inject({}) { |total, item|
      total[item.command] = item.input
      total }

    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"',
                                     'gpg2 --import',
                                     'gpg2 --import-ownertrust']
    users = executed.map { |e| e.user }.uniq
    users.should == ['root']
    env = executed.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/root']
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {'gpg2 --import' => 'thekeybitshere',
                               'gpg2 --import-ownertrust' => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'works properly when importing a public key that is not already there' do
    # arrange

    # act

    # assert
    pending 'Write this test'
  end

  it 'does not do anything if the correct public key is already there' do
    # arrange

    # act

    # assert
    pending 'Write this test'
  end

  it 'does not do anything if the correct private key is already there' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --with-fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
sec  2048R/390AA6C9 2014-08-17 pkg_key dev  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
        ssb  2048R/175EAAB1 2014-08-17
          EOF
        when 'gpg2 --list-secret-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
                      -----------------
                      sec   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                            Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
                      uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
                      sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    executed_cmdline = executed.inject({}) { |total, item|
      total[item.command] = item.input
      total }

    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"',
                                     'gpg2 --with-fingerprint',
                                     'gpg2 --list-secret-keys --fingerprint']
    users = executed.map { |e| e.user }.uniq
    users.should == ['root']
    env = executed.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/root']
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {'gpg2 --with-fingerprint' => 'thekeybitshere'}
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(false)
  end

  it 'does update the key if a different public key is already there' do
    # arrange

    # act

    # assert
    pending 'Write this test'
  end

  it 'does update the key if a different private key is already there' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --with-fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
sec  2048R/390AA6C9 2014-08-17 pkg_key dev  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
        ssb  2048R/175EAAB1 2014-08-17
          EOF
        when 'gpg2 --list-secret-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
              -----------------
              sec   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                    Key fingerprint = 6D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
              uid                  BSW Tech DB Backup db_prod (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
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
      bsw_gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    executed_cmdline = executed.inject({}) { |total, item|
      total[item.command] = item.input
      total }

    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"',
                                     'gpg2 --with-fingerprint',
                                     'gpg2 --list-secret-keys --fingerprint',
                                     'gpg2 --import',
                                     'gpg2 --import-ownertrust']
    users = executed.map { |e| e.user }.uniq
    users.should == ['root']
    env = executed.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/root']
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {'gpg2 --with-fingerprint' => 'thekeybitshere',
                               'gpg2 --import' => 'thekeybitshere',
                               'gpg2 --import-ownertrust' => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(true)
  end


  it 'works properly when run as a different user' do
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~someone_else"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/someone_else')
        when 'gpg2 --with-fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
sec  2048R/390AA6C9 2014-08-17 pkg_key dev  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
        ssb  2048R/175EAAB1 2014-08-17
          EOF
        when 'gpg2 --list-secret-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return ''
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
      bsw_gpg_key_manage 'someone_else' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    executed_cmdline = executed.inject({}) { |total, item|
      total[item.command] = item.input
      total }

    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~someone_else"',
                                     'gpg2 --with-fingerprint',
                                     'gpg2 --list-secret-keys --fingerprint',
                                     'gpg2 --import',
                                     'gpg2 --import-ownertrust']
    users = executed.map { |e| e.user }.uniq
    users.should == ['someone_else']
    env = executed.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/someone_else']
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {'gpg2 --with-fingerprint' => 'thekeybitshere',
                               'gpg2 --import' => 'thekeybitshere',
                               'gpg2 --import-ownertrust' => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'someone_else'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'overwrites the existing public key for the user if the fingerprint has changed' do
    # arrange

    # act

    # assert
    pending 'Write this test'
  end

  it 'overwrites the existing private key for the user if the fingerprint has changed' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --delete-secret-and-public-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9'
          shell_out.stub!(:error!)
        when 'gpg2 --with-fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return 'sec  2048R/390AA6C9 2014-08-17 BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
          ssb  2048R/175EAAB1 2014-08-17'
        when 'gpg2 --list-secret-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
              -----------------
              sec   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                    Key fingerprint = 6D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
              uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
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
      bsw_gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    executed_cmdline = executed.inject({}) { |total, item|
      total[item.command] = item.input
      total }

    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"',
                                     'gpg2 --with-fingerprint',
                                     'gpg2 --list-secret-keys --fingerprint',
                                     'gpg2 --delete-secret-and-public-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                     'gpg2 --import',
                                     'gpg2 --import-ownertrust']
    users = executed.map { |e| e.user }.uniq
    users.should == ['root']
    env = executed.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/root']
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {'gpg2 --with-fingerprint' => 'thekeybitshere',
                               'gpg2 --import' => 'thekeybitshere',
                               'gpg2 --import-ownertrust' => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'allows working with public key fingerprints from the recipe based on a PEM cert' do
    # arrange

    # act

    # assert
    pending 'Write this test'
  end

  it 'allows working with private key fingerprints from the recipe based on a PEM cert' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --with-fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
        sec  2048R/33AE3E6C 2014-08-17 pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>
              Key fingerprint = 7B11 C141 0667 3B53 46A6  5351 F44B 4C68 33AE 3E6C
        ssb  2048R/175EAAB1 2014-08-17
          EOF
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe <<-EOF
      key = get_draft_key_from_string 'thekeybitshere'
      file '/some/dummy/file' do
        content key.fingerprint
      end

      file '/some/dummy/file2' do
        content key.username
      end
    EOF

    # assert
    command = nil
    do_shift = lambda { command = executed.shift }
    do_shift.call
    command.command.should == 'gpg2 --with-fingerprint'
    command.input.should == 'thekeybitshere'
    expect(@chef_run).to render_file('/some/dummy/file').with_content('7B11 C141 0667 3B53 46A6  5351 F44B 4C68 33AE 3E6C')
    expect(@chef_run).to render_file('/some/dummy/file2').with_content('pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>')
  end

  it 'allows working with public key fingerprints from the recipe based on a cookbook file' do
    # arrange

    # act

    # assert
    pending 'Write this test'
  end

  it 'allows working with private key fingerprints from the recipe based on a cookbook file' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --with-fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
sec  2048R/390AA6C9 2014-08-17 BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
        ssb  2048R/175EAAB1 2014-08-17
          EOF
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end
    dev_environment = File.join(cookbook_path, 'files', 'default', 'dev')
    FileUtils.mkdir_p dev_environment
    File.open File.join(dev_environment, 'thefile.pub'), 'w' do |f|
      f << 'thekeybitshere'
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
    command = nil
    do_shift = lambda { command = executed.shift }
    do_shift.call
    command.command.should == 'gpg2 --with-fingerprint'
    command.input.should == 'thekeybitshere'
    expect(@chef_run).to render_file('/some/dummy/file').with_content('4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9')
    expect(@chef_run).to render_file('/some/dummy/file2').with_content('BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>')
  end

  it 'allows supplying Chef vault info for a private key directly as opposed to key contents' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --with-fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
        -----------------
        pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
              Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
        uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
        sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        when 'gpg2 --list-secret-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return ''
        when 'gpg2 --import'
          shell_out.stub!(:error!)
        when 'gpg2 --import-ownertrust'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end
    stub_vault_entry = {'json_key' => 'thekeybitshere'}
    ChefVault::Item.stub!(:load).with('thedatabag', 'the_item').and_return stub_vault_entry

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_key_manage 'root' do
        chef_vault_info :data_bag => 'thedatabag', :item=> 'the_item', :json_key => 'json_key'
      end
    EOF

    # assert
    executed_cmdline = executed.inject({}) { |total, item|
      total[item.command] = item.input
      total }

    executed_cmdline.keys.should == ['/bin/sh -c "echo -n ~root"',
                                     'gpg2 --with-fingerprint',
                                     'gpg2 --list-secret-keys --fingerprint',
                                     'gpg2 --import',
                                     'gpg2 --import-ownertrust']
    users = executed.map { |e| e.user }.uniq
    users.should == ['root']
    env = executed.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/root']
    input_specified = executed_cmdline.reject { |k, v| !v }
    input_specified.should == {'gpg2 --with-fingerprint' => 'thekeybitshere',
                               'gpg2 --import' => 'thekeybitshere',
                               'gpg2 --import-ownertrust' => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"}
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(true)
  end
end
