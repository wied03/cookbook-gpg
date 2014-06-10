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

  it 'works properly when importing a private key that is not already there' do
    # arrange
    # TODO: Get away a bit from inline resources and do more ourselves, using Ruby code to decide whether to execute or not
    temp_lwrp_recipe contents: <<-EOF
      gpg_key_manage 'the user <user@user.com>' do
        key_contents 'thekeybitshere'
      end
    EOF

    # act + assert
    # root will be default user
    pending 'Write this test'
  end

  it 'does not do anything if the private key is already there' do
    # arrange
    temp_lwrp_recipe contents: <<-EOF
      gpg_key_manage 'the user <user@user.com>' do
        key_contents 'thekeybitshere'
      end
    EOF
    # TODO: Arrange for same fingerprint for user to be there

    # act

    # assert
    pending 'Write this test'
  end

  it 'works properly when run as a different user' do
    # arrange
    temp_lwrp_recipe contents: <<-EOF
      gpg_key_manage 'the user <user@user.com>' do
        key_contents 'thekeybitshere'
        as_user 'someoneelse'
      end
    EOF

    # act

    # assert
    pending 'Write this test'
  end

  it 'overwrites the existing key for the user if the fingerprint has changed' do
    # arrange

    # act

    # assert
    pending 'Write this test'
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
