actions :replace
default_action :replace

attribute :for_user, :kind_of => String, :name_attribute => true
attribute :key_contents, :kind_of => String
attribute :chef_vault_info, :kind_of => Hash
attribute :key_type, :kind_of => Symbol, :default => :secret_key, :equal_to => [:public_key, :secret_key]
