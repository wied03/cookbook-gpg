# Encoding: utf-8

require_relative 'spec_helper'

describe 'Key contents LWRP - Root' do
  describe command('sudo -i gpg2 --list-sigs') do
    it {
      should return_stdout /.*pub   4096R\/B22D2CD5.*/
    }

    it 'should have trusted the key' do
      should return_stdout /.*sig 3.*/
    end
  end

  describe command('sudo -i gpg2 --list-secret-keys') do
    it { should return_stdout /.*sec   2048R\/C26E1EFE.*/ }
  end
end

describe 'Key Contents LWRP - Joe - Public Key - Non-default Keyring' do
  describe command('sudo -u joe -i gpg2 --list-sigs --no-default-keyring --keyring stuff.gpg') do
    it { should return_stdout /.*pub   4096R\/B22D2CD5.*/ }
    it 'should NOT have trusted the key because we are using non-default keyring' do
      should_not return_stdout /.sig 3.*/
      should return_stdout /.*sig 1.*/
    end
  end
end

describe 'Key Contents LWRP - Joe - Secret Key - Non-default Keyring' do
  describe command('sudo -u joe -i gpg2 --list-sigs --no-default-keyring --secret-keyring stuff_secret.gpg') do
    it { should return_stdout /.*sec   2048R\/C26E1EFE.*/ }
    it 'should NOT have trusted the key because non-default keyring' do
      should_not return_stdout /.sig 3.*/
      should return_stdout /.*sig 1.*/
    end
  end
end

describe 'Key Contents LWRP - Bob - Key server' do
  describe command('sudo -u bob -i gpg2 --list-sigs') do
    it { should return_stdout /.*pub   4096R\/AC40B2F7.*/ }

    it 'should have trusted the key' do
      should return_stdout /.*sig 3.*/
    end
  end
end

describe 'Key Contents LWRP - Seymour - Secret Key - Non-default Keyring' do
  describe command('sudo -u seymour -i gpg2 --list-sigs --no-default-keyring --secret-keyring stuff_secret.gpg') do
    it { should return_stdout /.*sec   2048R\/C26E1EFE.*/ }
    it 'should have trusted the key because we forced a trust' do
      should return_stdout /.sig 3.*/
    end
  end
end
