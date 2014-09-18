public_key_bits = cookbook_file_contents 'leo.pem', 'fake'
private_key_bits = cookbook_file_contents 'joe_secret.pem', 'fake'

with 'root' do |username|
  bsw_gpg_load_key_from_string 'some key' do
    for_user username
    key_contents public_key_bits
  end

  bsw_gpg_load_key_from_string 'some private key' do
    for_user username
    key_contents private_key_bits
  end
end

file '/tmp/joe_key_ran' do
  action :nothing
  content 'we got it!'
end

with 'joe' do |username|
  user_with_home(self, username)

  bsw_gpg_load_key_from_string 'keyring test with public key' do
    for_user username
    key_contents public_key_bits
    keyring_file_public 'stuff.gpg'
    notifies :create, 'file[/tmp/joe_key_ran]', :delayed
  end

  bsw_gpg_load_key_from_string 'keyring test with secret key' do
    for_user username
    key_contents private_key_bits
    keyring_file_secret 'stuff_secret.gpg'
    keyring_file_public 'stuff_public.gpg'
  end
end

with 'seymour' do |username|
  user_with_home(self, username)

  bsw_gpg_load_key_from_string 'keyring test with forced trust' do
    for_user username
    key_contents private_key_bits
    keyring_file_secret 'stuff_secret.gpg'
    keyring_file_public 'stuff_public.gpg'
    force_import_owner_trust true
  end
end

with 'john' do |username|
  user_with_home(self, username)

  bsw_gpg_load_key_from_string 'john private key' do
    for_user username
    key_contents private_key_bits
  end

  bsw_gpg_load_key_from_string 'john key in different keystore' do
    for_user username
    key_contents public_key_bits
    keyring_file_public 'stuff.gpg'
  end
end

multiple_bits = cookbook_file_contents 'multiple_id.pem', 'fake'

with 'jason' do |username|
  user_with_home(self, username)

  bsw_gpg_load_key_from_string 'jason key with multiple usernames' do
    for_user username
    key_contents multiple_bits
  end
end