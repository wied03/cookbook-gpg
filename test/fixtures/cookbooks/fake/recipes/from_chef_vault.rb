private_key_bits = cookbook_file_contents 'joe_secret.pem', 'fake'

node.default['build-essential']['compile_time'] = true
include_recipe 'build-essential::default'

# Need this to write to data bags, etc.
chef_gem 'cheffish' do
  version '5.0.0'
  compile_time true
end

chef_gem 'chef-vault' do
  compile_time true
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