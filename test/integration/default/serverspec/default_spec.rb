# Encoding: utf-8

require_relative 'spec_helper'

describe 'Key contents LWRP' do
  describe command('sudo -i gpg2 --list-keys') do
    it { should return_stdout /.*pub   4096R\/B22D2CD5.*/}
  end
end
