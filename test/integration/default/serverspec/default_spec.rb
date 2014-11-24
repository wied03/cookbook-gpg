# Encoding: utf-8

require_relative 'spec_helper'

describe 'Key contents LWRP - Root' do
  describe command('sudo -i gpg2 --list-keys') do
    its(:stdout) { should match /.*pub   4096R\/B22D2CD5.*/
    }
  end

  describe command('sudo -i gpg2 --export-ownertrust') do
    its(:stdout) { should match /.*C26E1EFE:6:$/ }
  end

  describe command('sudo -i gpg2 --list-secret-keys') do
    its(:stdout) { should match /.*sec   2048R\/C26E1EFE.*/ }
  end
end

describe 'Key Contents LWRP - Joe - Public Key - Non-default Keyring' do
  describe file('/tmp/joe_key_ran') do
    its(:content) { should eq 'we got it!' }
  end

  describe command('sudo -u joe -i gpg2 --list-keys --no-default-keyring --keyring stuff.gpg') do
    its(:stdout) { should match /.*pub   4096R\/B22D2CD5.*/ }
  end

  # non default keyring, owner trusts are 1 per user
  describe command('sudo -u joe -i gpg2 --export-ownertrust') do
    its(:stdout) { should_not match /.*B22D2CD5:6:$/ }
    its(:stdout) { should_not match /.*C26E1EFE:6:$/ }
  end
end

describe 'Key Contents LWRP - Joe - Secret Key - Non-default Keyring' do
  describe command('sudo -u joe -i gpg2 --list-secret-keys --no-default-keyring --secret-keyring stuff_secret.gpg --keyring stuff_public.gpg') do
    its(:stdout) { should match /.*sec   2048R\/C26E1EFE.*/ }
  end

  describe command('sudo -u joe -i gpg2 --list-keys --no-default-keyring --secret-keyring stuff_secret.gpg --keyring stuff_public.gpg') do
    its(:stdout) { should match /.*pub   2048R\/C26E1EFE.*/ }
  end
end

describe 'Key Contents LWRP - Bob - Key server' do
  describe command('sudo -u bob -i gpg2 --list-keys') do
    its(:stdout) { should match /.*pub   4096R\/AC40B2F7.*/ }
  end

  describe command('sudo -u bob -i gpg2 --export-ownertrust') do
    its(:stdout) { should_not match /.*AC40B2F7:6:$/ }
  end
end

describe 'Key Contents LWRP - Seymour - Secret Key - Non-default Keyring' do
  describe command('sudo -u seymour -i gpg2 --list-secret-keys --no-default-keyring --secret-keyring stuff_secret.gpg --keyring stuff_public.gpg') do
    its(:stdout) { should match /.*sec   2048R\/C26E1EFE.*/ }
  end

  describe command('sudo -u seymour -i gpg2 --list-keys --no-default-keyring --secret-keyring stuff_secret.gpg --keyring stuff_public.gpg') do
    its(:stdout) { should match /.*pub   2048R\/C26E1EFE.*/ }
  end

  # we forced a trust here
  describe command('sudo -u seymour -i gpg2 --export-ownertrust') do
    its(:stdout) { should match /.*C26E1EFE:6:$/ }
  end
end

describe 'Key Contents LWRP - John - Normal secret key + external public key' do
  describe command('sudo -u john -i gpg2 --export-ownertrust') do
    its(:stdout) { should match /.*C26E1EFE:6:$/ }
  end

  describe command('sudo -u john -i gpg2 --list-secret-keys') do
    its(:stdout) { should match /.*sec   2048R\/C26E1EFE.*/ }
  end

  describe command('sudo -u john -i gpg2 --list-keys --no-default-keyring --keyring stuff.gpg') do
    its(:stdout) {
      should match /.*pub   4096R\/B22D2CD5.*/
    }
  end
end

describe 'Key Contents LWRP - Walt - Chef vault provided key' do
  describe command('sudo -u walt -i gpg2 --list-secret-keys') do
    its(:stdout) { should match /.*sec   2048R\/C26E1EFE.*/ }
  end
end

describe 'Key Contents LWRP - Jason - 2 user IDs' do
  describe command('sudo -u jason -i gpg2 --list-keys') do
    its(:stdout) { should match /.*pub   2048R\/F291A664.*/ }
    its(:stdout) { should match /.*uid\s+John Doe <john2@doe2.com>.*/ }
    its(:stdout) { should match /.*uid\s+John Doe <john@doe.com>.*/ }
  end
end