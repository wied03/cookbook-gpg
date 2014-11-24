include_recipe 'bsw_gpg::default'

chef_gem 'with'
require 'with'

selinux_state 'SELinux Compatible' do
  action :enforcing
end

include_recipe 'fake::from_string'
include_recipe 'fake::from_key_server'
include_recipe 'fake::from_chef_vault'