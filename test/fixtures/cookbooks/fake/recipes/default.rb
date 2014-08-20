include_recipe 'bsw_gpg::default'

chef_gem 'with'
require 'with'

key_bits = cookbook_file_contents 'leo.pub', 'fake'
bsw_gpg_load_key_from_string 'some key' do
  for_user 'root'
  key_contents key_bits
end

with 'joe' do |username|
  user username do
    supports :manage_home => true
  end

  bsw_gpg_load_key_from_string 'keyring test' do
    for_user username
    key_contents key_bits
    keyring_file 'stuff.gpg'
  end
end

with 'bob' do |username|
  user username do
    supports :manage_home => true
  end

  bsw_gpg_load_key_from_server 'from key server test' do
    for_user username
    key_server 'keyserver.ubuntu.com'
    key_id '561F9B9CAC40B2F7'
  end
end

