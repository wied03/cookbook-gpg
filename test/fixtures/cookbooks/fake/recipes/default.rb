include_recipe 'bsw_gpg::default'

chef_gem 'with' do
  compile_time true
end
require 'with'

include_recipe 'fake::from_string'
include_recipe 'fake::from_key_server'
include_recipe 'fake::from_chef_vault'