include_recipe 'bsw_gpg::default'

chef_gem 'with'
require 'with'

public_key_bits = cookbook_file_contents 'leo.pem', 'fake'
private_key_bits = cookbook_file_contents 'joe_secret.pem', 'fake'

bsw_gpg_load_key_from_string 'some key' do
  for_user 'root'
  key_contents public_key_bits
end

bsw_gpg_load_key_from_string 'some private key' do
  for_user 'root'
  key_contents private_key_bits
end

user_with_home = lambda do |username|
  user username do
    action :create
    supports :manage_home => true
    home "/home/#{username}"
  end
end

with 'joe' do |username|
  user_with_home[username]

  bsw_gpg_load_key_from_string 'keyring test with public key' do
    for_user username
    key_contents public_key_bits
    keyring_file 'stuff.gpg'
  end

  bsw_gpg_load_key_from_string 'keyring test with secret key' do
    for_user username
    key_contents private_key_bits
    keyring_file 'stuff_secret.gpg'
  end
end

with 'bob' do |username|
  user_with_home[username]

  bsw_gpg_load_key_from_key_server 'from key server test' do
    for_user username
    key_server 'keyserver.ubuntu.com'
    key_id '561F9B9CAC40B2F7'
  end
end

