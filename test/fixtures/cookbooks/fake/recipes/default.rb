include_recipe 'bsw_gpg::default'

chef_gem 'with'
require 'with'

include_recipe 'fake::from_string'
include_recipe 'fake::from_key_server'
include_recipe 'fake::from_chef_vault'