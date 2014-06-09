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
      gpg_key_manage 'stuff' do
        key_filename 'thekey.gpg'
      end
    EOF

    # act + assert
    expect(@chef_run).to run_execute('echo foobar')
    # assert
    pending 'Write this test'
  end
end
