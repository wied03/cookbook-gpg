private_key_bits = cookbook_file_contents 'joe_secret.pem', 'fake'

# Need this to write to data bags, etc.
chef_gem 'cheffish' do
  version '0.7.1'
end

chef_gem 'chef-vault' do
  version '2.2.1'
end

require 'cheffish'
require 'chef-vault'

with 'walt', 'a-secret-one', 'an-item' do |username, data_bag_name, vault_item|
  item = ChefVault::Item.new(data_bag_name, vault_item)
  item.clients('*:*')
  item['json_key'] = private_key_bits
  item.save

  user_with_home(self, username)

  bsw_gpg_load_key_from_chef_vault 'vault key' do
    data_bag data_bag_name
    item vault_item
    json_key 'json_key'
    for_user username
  end
end