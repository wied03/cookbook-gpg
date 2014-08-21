# Encoding: utf-8

require_relative 'spec_helper'
require 'chef-vault'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'helper_gpg_interface'
require 'helper_key_header'

describe 'gpg::lwrp:load_key_from_string' do
  include BswTech::ChefSpec::LwrpTestHelper

  def cookbook_under_test
    'bsw_gpg'
  end

  def lwrps_under_test
    'load_key_from_string'
  end

  ['key_contents', 'for_user'].each do |attr_to_include|
    it "fails if we only supply #{attr_to_include}" do
      # arrange

      # act
      action = lambda {
        temp_lwrp_recipe <<-EOF
          bsw_gpg_load_key_from_string 'some key' do
            #{attr_to_include} 'value'
          end
        EOF
      }

      # assert
      expect(action).to raise_exception Chef::Exceptions::ValidationFailed
    end
  end

  it 'works properly when importing a secret key that is not already there' do
    # arrange
    stub_gpg_interface(draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:secret_key))
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import',
                                :expected_input => '-----BEGIN PGP PRIVATE KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

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
    expect(@keyring_checked).to eq(:default)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'works properly when importing a public key that is not already there' do
    stub_gpg_interface(draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:public_key))

    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import',
                                :expected_input => '-----BEGIN PGP PUBLIC KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

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
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'does not do anything if the correct public key is already there' do
    key = BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                      username='the username',
                                      id='the id',
                                      type=:public_key)
    stub_gpg_interface(current=[key], draft=key)
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            }
                        ])

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
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(false)
  end

  it 'does not do anything if the correct secret key is already there' do
    # arrange
    key = BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                      username='the username',
                                      id='the id',
                                      type=:secret_key)
    stub_gpg_interface(current=[key], draft=key)
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            }
                        ])

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
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(false)
  end

  it 'does update the key if a different public key is already there' do
    # arrange
    current_key = BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                              username='the username',
                                              id='the id',
                                              type=:public_key)
    new_key = BswTech::Gpg::KeyHeader.new(fingerprint='5D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                          username='the username 2',
                                          id='the id',
                                          type=:public_key)
    stub_gpg_interface(current=[current_key], draft=new_key)
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import',
                                :expected_input => '-----BEGIN PGP PUBLIC KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import-ownertrust',
                                :expected_input => "5D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

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
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'does update the key if a different secret key is already there' do
    # arrange
    current_key = BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                              username='the username',
                                              id='the id',
                                              type=:secret_key)
    new_key = BswTech::Gpg::KeyHeader.new(fingerprint='5D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                          username='the username 2',
                                          id='the id',
                                          type=:secret_key)
    stub_gpg_interface(current=[current_key], draft=new_key)
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import',
                                :expected_input => '-----BEGIN PGP PRIVATE KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import-ownertrust',
                                :expected_input => "5D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

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
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end


  it 'runs the commands as the proper user' do
    # arrange
    stub_gpg_interface(draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:secret_key))
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~someone_else"',
                                :stdout => '/home/someone_else'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import',
                                :expected_input => '-----BEGIN PGP PRIVATE KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])
    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PRIVATE KEY BLOCK-----'
        for_user 'someone_else'
      end
    EOF

    # assert
    users = @shell_outs.map { |e| e.user }.uniq
    users.should == ['someone_else']
    env = @shell_outs.map { |e| e.environment['HOME'] }.uniq
    # 1st call is to get home dir, so won't be there yet
    env.should == [nil, '/home/someone_else']
  end

  it 'overwrites the existing public key for the user if the fingerprint has changed' do
    # arrange
    current = BswTech::Gpg::KeyHeader.new(fingerprint='6D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                          username='the username',
                                          id='the id',
                                          type=:public_key)
    stub_gpg_interface(current=[current],
                   draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:public_key))
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --delete-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import',
                                :expected_input => '-----BEGIN PGP PUBLIC KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

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
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'overwrites the existing secret key for the user if the fingerprint has changed' do
    # arrange
    current = BswTech::Gpg::KeyHeader.new(fingerprint='6D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                          username='the username',
                                          id='the id',
                                          type=:secret_key)
    stub_gpg_interface(current=[current],
                   draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:secret_key))
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --delete-secret-and-public-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import',
                                :expected_input => '-----BEGIN PGP PRIVATE KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

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
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'allows specifying a custom keyring file with a public key' do
    # arrange
    stub_gpg_interface(draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:public_key))
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --keyring something.gpg --import',
                                :expected_input => '-----BEGIN PGP PUBLIC KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --keyring something.gpg --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

    # act
    temp_lwrp_recipe <<-EOF
        bsw_gpg_load_key_from_string 'some key' do
          key_contents '-----BEGIN PGP PUBLIC KEY BLOCK-----'
          for_user 'root'
          keyring_file 'something.gpg'
        end
    EOF

    # assert
    expect(@current_type_checked).to eq(:public_key)
    expect(@external_type).to eq(:public_key)
    expect(@keyring_checked).to eq('something.gpg')
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'allows specifying a custom keyring file with a secret key' do
    stub_gpg_interface(draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:secret_key))
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --secret-keyring something.gpg --import',
                                :expected_input => '-----BEGIN PGP PRIVATE KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --secret-keyring something.gpg --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

    # act
    temp_lwrp_recipe <<-EOF
        bsw_gpg_load_key_from_string 'some key' do
          key_contents '-----BEGIN PGP PRIVATE KEY BLOCK-----'
          for_user 'root'
          keyring_file 'something.gpg'
        end
    EOF

    # assert
    expect(@current_type_checked).to eq(:secret_key)
    expect(@external_type).to eq(:secret_key)
    expect(@keyring_checked).to eq('something.gpg')
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'removes a public key from only the custom keyring when a keyring is specified and removal is required' do
    # assert
    current = BswTech::Gpg::KeyHeader.new(fingerprint='6D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                          username='the username',
                                          id='the id',
                                          type=:public_key)
    stub_gpg_interface(current=[current],
                   draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:public_key))
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --keyring something.gpg --delete-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --keyring something.gpg --import',
                                :expected_input => '-----BEGIN PGP PUBLIC KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --keyring something.gpg --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PUBLIC KEY BLOCK-----'
        for_user 'root'
        keyring_file 'something.gpg'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:public_key)
    expect(@external_type).to eq(:public_key)
    expect(@base64_used).to eq('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end

  it 'removes a secret key from only the custom keyring when a keyring is specified and removal is required' do
    # arrange
    current = BswTech::Gpg::KeyHeader.new(fingerprint='6D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                          username='the username',
                                          id='the id',
                                          type=:secret_key)
    stub_gpg_interface(current=[current],
                   draft=BswTech::Gpg::KeyHeader.new(fingerprint='4D1CF3288469F260C2119B9F76C95D74390AA6C9',
                                                     username='the username',
                                                     id='the id',
                                                     type=:secret_key))
    setup_stub_commands([
                            {
                                :command => '/bin/sh -c "echo -n ~root"',
                                :stdout => '/home/root'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --secret-keyring something.gpg --delete-secret-and-public-key --batch --yes 6D1CF3288469F260C2119B9F76C95D74390AA6C9'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --secret-keyring something.gpg --import',
                                :expected_input => '-----BEGIN PGP PRIVATE KEY BLOCK-----'
                            },
                            {
                                :command => 'gpg2 --no-auto-check-trustdb --no-default-keyring --secret-keyring something.gpg --import-ownertrust',
                                :expected_input => "4D1CF3288469F260C2119B9F76C95D74390AA6C9:6:\n"
                            }
                        ])

    # act
    temp_lwrp_recipe <<-EOF
      bsw_gpg_load_key_from_string 'some key' do
        key_contents '-----BEGIN PGP PRIVATE KEY BLOCK-----'
        for_user 'root'
        keyring_file 'something.gpg'
      end
    EOF

    # assert
    expect(@current_type_checked).to eq(:secret_key)
    expect(@external_type).to eq(:secret_key)
    expect(@base64_used).to eq('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    verify_actual_commands_match_expected
    resource = @chef_run.find_resource 'bsw_gpg_load_key_from_string', 'some key'
    expect(resource.updated_by_last_action?).to eq(true)
  end
end
