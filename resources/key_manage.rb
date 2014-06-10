actions :replace
default_action :replace

attribute :key_name, :kind_of => String, :name_attribute => true
attribute :key_contents, :kind_of => String
attribute :as_user, :kind_of => String, :default => 'root'
