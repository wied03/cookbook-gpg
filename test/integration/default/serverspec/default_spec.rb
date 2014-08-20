# Encoding: utf-8

require_relative 'spec_helper'

describe 'Key contents LWRP - Root' do
  describe command('sudo -i gpg2 --list-keys') do
    it { should return_stdout /.*pub   4096R\/B22D2CD5.*/ }
  end
end

describe 'Key Contents LWRP - Joe - Public Key' do
  describe command('sudo -u joe -i gpg2 --list-keys --no-default-keyring --keyring stuff.gpg') do
    it { should return_stdout /.*pub   4096R\/B22D2CD5.*/ }
  end
end

describe 'Key Contents LWRP - Bob - Key server' do
  describe command('sudo -u bob -i gpg2 --list-keys') do
    it { should return_stdout /.*pub   4096R\/CAC40B2F7.*/ }
  end
end
