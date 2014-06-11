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
    'gpg'
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
    Tempfile.stub!(:new) do
      name = "temp_file_#{@open_tempfiles.length}"
      @open_tempfiles << name
      temp_file = double()
      temp_file.stub(:path).and_return(name)
      temp_file.stub(:close!) do
        @open_tempfiles.delete name
      end
      temp_file
    end
  }

  it 'works properly when importing a private key that is not already there' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
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
        when 'shred -n 20 -z temp_file_0'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe contents: <<-EOF
      gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    expect(executed).to have(5).items
    executed[0].user.should == 'root'
    executed[0].input.should == 'thekeybitshere'
    executed[1].user.should == 'root'
    executed[2].user.should == 'root'
    executed[3].user.should == 'root'
    executed[3].input.should == 'thekeybitshere'
    executed[4].user.should == 'root'
    resource = @chef_run.find_resource 'gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'does not do anything if the correct private key is already there' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
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
        when 'shred -n 20 -z temp_file_0'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe contents: <<-EOF
      gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    expect(executed).to have(4).items
    executed[0].user.should == 'root'
    executed[0].input.should == 'thekeybitshere'
    executed[1].user.should == 'root'
    executed[2].user.should == 'root'
    executed[3].user.should == 'root'
    resource = @chef_run.find_resource 'gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(false)
  end

  it 'does update the key if a different private key is already there' do
    # arrange
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
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
        when 'shred -n 20 -z temp_file_0'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe contents: <<-EOF
      gpg_key_manage 'root' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    expect(executed).to have(5).items
    executed[0].user.should == 'root'
    executed[0].input.should == 'thekeybitshere'
    executed[1].user.should == 'root'
    executed[2].user.should == 'root'
    executed[3].user.should == 'root'
    executed[3].input.should == 'thekeybitshere'
    executed[4].user.should == 'root'
    resource = @chef_run.find_resource 'gpg_key_manage', 'root'
    expect(resource.updated_by_last_action?).to eq(true)
  end


  it 'works properly when run as a different user' do
    executed = []
    @stub_setup = lambda do |shell_out|
      executed << shell_out
      case shell_out.command
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
        when 'shred -n 20 -z temp_file_0'
          shell_out.stub!(:error!)
        else
          shell_out.stub(:error!).and_raise "Unexpected command #{shell_out.command}"
      end
    end

    # act
    temp_lwrp_recipe contents: <<-EOF
      gpg_key_manage 'someone_else' do
        key_contents 'thekeybitshere'
      end
    EOF

    # assert
    expect(executed).to have(5).items
    executed[0].user.should == 'someone_else'
    executed[0].input.should == 'thekeybitshere'
    executed[1].user.should == 'someone_else'
    executed[2].user.should == 'someone_else'
    executed[3].user.should == 'someone_else'
    executed[3].input.should == 'thekeybitshere'
    executed[4].user.should == 'someone_else'
    resource = @chef_run.find_resource 'gpg_key_manage', 'someone_else'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'overwrites the existing key for the user if the fingerprint has changed' do
    # arrange

    # act

    # assert
    pending 'Write this test'
    pending 'test the updated set to true on new_resource, use standard approach in bsw_pgsql cookbook'
  end

  it 'removes the temporary private key file if gpg fails for any reason' do
    # arrange
    temp_lwrp_recipe contents: <<-EOF
      gpg_key_manage 'the user <user@user.com>' do
        key_contents 'thekeybitshere'
      end
    EOF

    # act + assert
    pending 'Write this test'
  end
end
