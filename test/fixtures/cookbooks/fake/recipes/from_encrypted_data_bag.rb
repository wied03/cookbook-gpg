with 'edward', 'fake', 'encrypted_data_bag' do |username, data_bag_name, vault_item|
  user_with_home(self, username)

  bsw_gpg_load_key_from_encrypted_data_bag 'encrypted data bag key' do
    data_bag data_bag_name
    item vault_item
    secret 'encrypted_data_bag_secret'
    json_key 'private_key'
    for_user username
  end
end