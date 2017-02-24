with 'den', 'fake', 'data_bag' do |username, data_bag_name, vault_item|
  user_with_home(self, username)

  bsw_gpg_load_key_from_data_bag 'data bag key' do
    data_bag data_bag_name
    item vault_item
    json_key 'public_key'
    for_user username
  end
end