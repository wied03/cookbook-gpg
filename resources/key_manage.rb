actions :replace
default_action :replace

attribute :for_user, :kind_of => String, :required => true
attribute :key_contents, :kind_of => String
attribute :chef_vault_info, :kind_of => Hash
