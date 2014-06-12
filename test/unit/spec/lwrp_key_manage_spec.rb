# Encoding: utf-8

require_relative 'spec_helper'

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
    @open_tempfiles = []
    @written_to_files = {}
    Dir::Tmpname.stub!(:create) do
      name = "temp_file_#{@open_tempfiles.length}"
      @open_tempfiles << name
      name
    end
    Tempfile.stub!(:new) do |prefix|
      temp_file_stub = double()
      name = "temp_file_#{@open_tempfiles.length}"
      @open_tempfiles << name
      temp_file_stub.stub!(:path).and_return "/path/to/#{name}"
      temp_file_stub.stub!(:close)
      temp_file_stub.stub!(:unlink)
      temp_file_stub.stub!(:'<<') do |text|
        @written_to_files[name] = text
      end
      temp_file_stub
    end
  }

  it 'works properly when importing a private key that is not already there' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --import --no-default-keyring --secret-keyring temp_file_0 --keyring temp_file_1'
          shell_out.stub!(:error!)
        when 'gpg2 --list-keys --fingerprint --no-default-keyring --keyring temp_file_1'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
        -----------------
        pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
              Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
        uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
        sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        when 'gpg2 --list-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return ''
        when 'gpg2 --import'
          shell_out.stub!(:error!)
        when 'shred -n 20 -z -u temp_file_0'
          shell_out.stub!(:error!)
        when 'gpg2 --import-ownertrust'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe contents: <<-EOF
      bsw_gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    command = nil
    do_shift = lambda { command = executed.shift }
    do_shift.call
    command.user.should == 'root'
    command.command.should == '/bin/sh -c "echo -n ~root"'
    do_shift.call
    command.user.should == 'root'
    command.input.should == 'thekeybitshere'
    command.environment['HOME'].should == '/home/root'
    do_shift.call
    command.user.should == 'root'
    command.environment['HOME'].should == '/home/root'
    do_shift.call
    command.user.should == 'root'
    command.environment['HOME'].should == '/home/root'
    do_shift.call
    command.user.should == 'root'
    command.input.should == 'thekeybitshere'
    command.environment['HOME'].should == '/home/root'
    do_shift.call
    command.user.should == 'root'
    command.environment['HOME'].should == '/home/root'
    command.command.should == 'gpg2 --import-ownertrust'
    command.input.should == "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
    do_shift.call
    command.user.should == 'root'
    expect(executed).to be_empty
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(true)
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
        when 'gpg2 --import --no-default-keyring --secret-keyring temp_file_0 --keyring temp_file_1'
          shell_out.stub!(:error!)
        when 'gpg2 --list-keys --fingerprint --no-default-keyring --keyring temp_file_1'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
            -----------------
            pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                  Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
            uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
            sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        when 'gpg2 --list-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
                      -----------------
                      pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                            Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
                      uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
                      sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        when 'shred -n 20 -z -u temp_file_0'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe contents: <<-EOF
      bsw_gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    command = nil
    do_shift = lambda { command = executed.shift }
    do_shift.call
    command.user.should == 'root'
    command.command.should == '/bin/sh -c "echo -n ~root"'
    do_shift.call
    command.user.should == 'root'
    command.input.should == 'thekeybitshere'
    do_shift.call
    command.user.should == 'root'
    do_shift.call
    command.user.should == 'root'
    do_shift.call
    command.user.should == 'root'
    expect(executed).to be_empty
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(false)
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
        when 'gpg2 --import --no-default-keyring --secret-keyring temp_file_0 --keyring temp_file_1'
          shell_out.stub!(:error!)
        when 'gpg2 --list-keys --fingerprint --no-default-keyring --keyring temp_file_1'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
              -----------------
              pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                    Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
              uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        when 'gpg2 --list-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
              -----------------
              pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                    Key fingerprint = 6D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
              uid                  BSW Tech DB Backup db_prod (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        when 'gpg2 --import'
          shell_out.stub!(:error!)
        when 'shred -n 20 -z -u temp_file_0'
          shell_out.stub!(:error!)
        when 'gpg2 --import-ownertrust'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe contents: <<-EOF
      bsw_gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    command = nil
    do_shift = lambda { command = executed.shift }
    do_shift.call
    command.user.should == 'root'
    command.command.should == '/bin/sh -c "echo -n ~root"'
    do_shift.call
    command.user.should == 'root'
    command.input.should == 'thekeybitshere'
    do_shift.call
    command.user.should == 'root'
    do_shift.call
    command.user.should == 'root'
    do_shift.call
    command.user.should == 'root'
    command.input.should == 'thekeybitshere'
    do_shift.call
    command.command.should == 'gpg2 --import-ownertrust'
    do_shift.call
    command.user.should == 'root'
    expect(executed).to be_empty
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
        when 'gpg2 --import --no-default-keyring --secret-keyring temp_file_0 --keyring temp_file_1'
          shell_out.stub!(:error!)
        when 'gpg2 --list-keys --fingerprint --no-default-keyring --keyring temp_file_1'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
        -----------------
        pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
              Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
        uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
        sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        when 'gpg2 --list-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return ''
        when 'gpg2 --import'
          shell_out.stub!(:error!)
        when 'shred -n 20 -z -u temp_file_0'
          shell_out.stub!(:error!)
        when 'gpg2 --import-ownertrust'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe contents: <<-EOF
      bsw_gpg_key_manage 'someone_else' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    command = nil
    do_shift = lambda { command = executed.shift }
    do_shift.call
    command.user.should == 'someone_else'
    command.command.should == '/bin/sh -c "echo -n ~someone_else"'
    do_shift.call
    command.user.should == 'someone_else'
    command.input.should == 'thekeybitshere'
    do_shift.call
    command.user.should == 'someone_else'
    do_shift.call
    command.user.should == 'someone_else'
    do_shift.call
    command.user.should == 'someone_else'
    command.input.should == 'thekeybitshere'
    do_shift.call
    command.command.should == 'gpg2 --import-ownertrust'
    do_shift.call
    command.user.should == 'someone_else'
    expect(executed).to be_empty
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'someone_else'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'overwrites the existing key for the user if the fingerprint has changed' do
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
        when 'gpg2 --import --no-default-keyring --secret-keyring temp_file_0 --keyring temp_file_1'
          shell_out.stub!(:error!)
        when 'gpg2 --list-keys --fingerprint --no-default-keyring --keyring temp_file_1'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
              -----------------
              pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                    Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
              uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        when 'gpg2 --list-keys --fingerprint'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return <<-EOF
              -----------------
              pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                    Key fingerprint = 6D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
              uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
              sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
          EOF
        when 'gpg2 --import'
          shell_out.stub!(:error!)
        when 'shred -n 20 -z -u temp_file_0'
          shell_out.stub!(:error!)
        when 'gpg2 --import-ownertrust'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe contents: <<-EOF
      bsw_gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    command = nil
    do_shift = lambda { command = executed.shift }
    do_shift.call
    command.user.should == 'root'
    command.command.should == '/bin/sh -c "echo -n ~root"'
    do_shift.call
    command.user.should == 'root'
    command.command.should include 'import'
    command.command.should include '--secret-keyring'
    command.input.should == 'thekeybitshere'
    do_shift.call
    command.user.should == 'root'
    command.command.should include 'list-keys'
    command.command.should include 'no-default-keyring'
    do_shift.call
    command.user.should == 'root'
    command.command.should include 'list-keys'
    do_shift.call
    command.command.should include 'delete'
    command.user.should == 'root'
    do_shift.call
    command.input.should == 'thekeybitshere'
    command.user.should == 'root'
    command.command.should == 'gpg2 --import'
    do_shift.call
    command.command.should == 'gpg2 --import-ownertrust'
    do_shift.call
    command.command.should include('shred')
    command.user.should == 'root'
    resource = @chef_run.find_resource 'bsw_gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'removes the temporary private key file if gpg fails for any reason' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
        when '/bin/sh -c "echo -n ~root"'
          shell_out.stub!(:error!)
          shell_out.stub!(:stdout).and_return('/home/root')
        when 'gpg2 --import --no-default-keyring --secret-keyring temp_file_0 --keyring temp_file_1'
          shell_out.stub!(:error!).and_raise 'GPG problem'
        when 'shred -n 20 -z -u temp_file_0'
          shell_out.stub!(:error!)
      end
    end
    removed = []
    FileUtils.stub!(:rm_rf) { |file| removed << file }

    # act
    lambda { temp_lwrp_recipe contents: <<-EOF
      bsw_gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF
    }.should raise_exception 'bsw_gpg_key_manage[root] (lwrp_gen::default line 1) had an error: RuntimeError: GPG problem'

    # assert
    executed[2].command.should == 'shred -n 20 -z -u temp_file_0'
    removed.should include 'temp_file_1'
    removed.should include 'temp_file_1~' # junk created by gpg
  end
end
