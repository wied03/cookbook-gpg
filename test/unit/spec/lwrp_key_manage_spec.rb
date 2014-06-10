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

  it 'works properly when importing a private key' do
    # arrange
    temp_lwrp_recipe contents: <<-EOF
      gpg_key_manage 'theuser' do
        key_contents 'thekeybitshere'
      end
    EOF

    # act + assert
    resource = @chef_run.find_resource('file', '/tmp/chef_gpg_import.key')
    resource.should_not be_nil
    expect(resource.owner).to eq 'theuser'
    expect(resource.content).to eq 'thekeybitshere'
    resource = @chef_run.find_resource('execute', 'gpg2 --import /tmp/chef_gpg_import.key || shred -n 20 -z -u /tmp/chef_gpg_import.key')
    resource.should_not be_nil
    expect(resource.user).to eq 'theuser'
    expect(@chef_run).to run_execute('shred -n 20 -z -u /tmp/chef_gpg_import.key')
  end

  it 'removes the temporary private key file if gpg fails for any reason' do
    # arrange
    temp_lwrp_recipe contents: <<-EOF
          gpg_key_manage 'theuser' do
            key_contents 'thekeybitshere'
          end
    EOF

    # act + assert
    resource = @chef_run.find_resource('execute', 'gpg2 --import /tmp/chef_gpg_import.key || shred -n 20 -z -u /tmp/chef_gpg_import.key')
    resource.should_not be_nil
  end
end
