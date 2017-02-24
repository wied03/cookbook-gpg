# Encoding: utf-8

require_relative 'spec_helper'

describe 'Key contents LWRP - Root' do
  describe command('sudo -i gpg2 --batch --no-tty --list-keys --with-colons') do
    its(:stdout) { should match /^pub:[^:]*:4096:1:DF4FD2ABB22D2CD5/
    }
  end

  describe command('sudo -i gpg2 --batch --no-tty --export-ownertrust') do
    its(:stdout) { should match /.*E708B60D0514625A:6:$/ }
  end

  describe command('sudo -i gpg2 --batch --no-tty --list-secret-keys --with-colons') do
    its(:stdout) { should match /^sec:[^:]*:2048:1:E708B60D0514625A/ }
  end
end

describe 'Key Contents LWRP - Joe - Public Key - Non-default Keyring' do
  describe file('/tmp/joe_key_ran') do
    its(:content) { should eq 'we got it!' }
  end

  describe command('sudo -u joe -i gpg2 --batch --no-tty --list-keys --with-colons --no-default-keyring --keyring stuff.gpg') do
    its(:stdout) { should match /^pub:[^:]*:4096:1:DF4FD2ABB22D2CD5/ }
  end

  # non default keyring, owner trusts are 1 per user
  describe command('sudo -u joe -i gpg2 --batch --no-tty --export-ownertrust') do
    its(:stdout) { should_not match /.*DF4FD2ABB22D2CD5:6:$/ }
    its(:stdout) { should_not match /.*E708B60D0514625A:6:$/ }
  end
end

describe 'Key Contents LWRP - Joe - Secret Key - Non-default Keyring' do
  describe command('sudo -u joe -i gpg2 --batch --no-tty --list-secret-keys --with-colons --no-default-keyring --secret-keyring stuff_secret.gpg --keyring stuff_public.gpg') do
    its(:stdout) { should match /^sec:[^:]*:2048:1:E708B60D0514625A/ }
  end

  describe command('sudo -u joe -i gpg2 --batch --no-tty --list-keys --with-colons --no-default-keyring --secret-keyring stuff_secret.gpg --keyring stuff_public.gpg') do
    its(:stdout) { should match /^pub:[^:]*:2048:1:E708B60D0514625A/ }
  end
end

describe 'Key Contents LWRP - Bob - Key server' do
  describe command('sudo -u bob -i gpg2 --batch --no-tty --list-keys --with-colons') do
    its(:stdout) { should match /^pub:[^:]*:4096:1:561F9B9CAC40B2F7/ }
  end

  describe command('sudo -u bob -i gpg2 --batch --no-tty --export-ownertrust') do
    its(:stdout) { should_not match /.*561F9B9CAC40B2F7:6:$/ }
  end
end

describe 'Key Contents LWRP - Seymour - Secret Key - Non-default Keyring' do
  describe command('sudo -u seymour -i gpg2 --batch --no-tty --list-secret-keys --with-colons --no-default-keyring --secret-keyring stuff_secret.gpg --keyring stuff_public.gpg') do
    its(:stdout) { should match /^sec:[^:]*:2048:1:E708B60D0514625A/ }
  end

  describe command('sudo -u seymour -i gpg2 --batch --no-tty --list-keys --with-colons --no-default-keyring --secret-keyring stuff_secret.gpg --keyring stuff_public.gpg') do
    its(:stdout) { should match /^pub:[^:]*:2048:1:E708B60D0514625A/ }
  end

  # we forced a trust here
  describe command('sudo -u seymour -i gpg2 --batch --no-tty --export-ownertrust') do
    its(:stdout) { should match /.*E708B60D0514625A:6:$/ }
  end
end

describe 'Key Contents LWRP - John - Normal secret key + external public key' do
  describe command('sudo -u john -i gpg2 --batch --no-tty --export-ownertrust') do
    its(:stdout) { should match /.*E708B60D0514625A:6:$/ }
  end

  describe command('sudo -u john -i gpg2 --batch --no-tty --list-secret-keys --with-colons') do
    its(:stdout) { should match /^sec:[^:]*:2048:1:E708B60D0514625A/ }
  end

  describe command('sudo -u john -i gpg2 --batch --no-tty --list-keys --with-colons --no-default-keyring --keyring stuff.gpg') do
    its(:stdout) {
      should match /^pub:[^:]*:4096:1:DF4FD2ABB22D2CD5/
    }
  end
end

describe 'Key Contents LWRP - Walt - Chef vault provided key' do
  describe command('sudo -u walt -i gpg2 --batch --no-tty --list-secret-keys --with-colons') do
    its(:stdout) { should match /^sec:[^:]*:2048:1:E708B60D0514625A/ }
  end
end

describe 'Key Contents LWRP - Jason - 2 user IDs' do
  describe command('sudo -u jason -i gpg2 --batch --no-tty --list-keys --with-colons') do
    its(:stdout) { should match /^pub:[^:]*:2048:1:F6CB10D5990621B2/ }
    its(:stdout) { should match /^uid:([^:]*:){8}John Doe <john2@doe2.com>/ }
    its(:stdout) { should match /^uid:([^:]*:){8}John Doe <john@doe.com>/ }
  end
end
