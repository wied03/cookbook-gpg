private_key_bits = cookbook_file_contents 'joe_secret.pem', 'fake'

chef_gem 'cheffish' do
  version '0.7.1'
end

chef_gem 'chef-vault' do
  version '2.2.1'
end

require 'cheffish'
require 'chef-vault' # for my testing

with 'walt', 'a-secret-one', 'an-item' do |username, data_bag_name, vault_item|
  # This is returning results
  #stuff = search(:node,'*:*')
  #puts "stuff is #{stuff}"
  # query = Chef::Search::Query.new
  # result = query.search(:node, '*:*')
  # puts "manual result is #{result}"
  #
  #
  item = ChefVault::Item.new(data_bag_name, vault_item)
  item.clients('*:*')
  #item.admins('')
  # this is not
  item['json_key'] = private_key_bits
  item.save

  # chef_vault_secret vault_item do
  #   data_bag data_bag_name
  #   raw_data({'json_key' => private_key_bits})
  #   #admins 'dummy_admin'
  #   admins ''
  #   search '*:*'
  # end


  ruby_block 'stuff' do
    block do
      puts "output of data bags dir: "+`cat /tmp/kitchen/data_bags/a-secret-one/an-item.json`
    end
  end

  user_with_home(self, username)

  bsw_gpg_load_key_from_chef_vault 'vault key' do
    data_bag data_bag_name
    item vault_item
    json_key 'json_key'
    for_user username
  end
end